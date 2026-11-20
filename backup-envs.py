#!/usr/bin/env python3
"""
Encrypted .env Backup — Collect ALL .env files from workspace, encrypt with Fernet.
Usage: python3 backup-envs.py [backup|restore|list|verify]

backup  : Scan workspace for .env files (excluding templates/examples), encrypt to .vault/envs.enc
restore : Decrypt .vault/envs.enc and write files back to their original paths
list    : Show files in the vault without decrypting
verify  : Decrypt and verify a wallet address matches (requires WALLET_ADDRESS env var)
"""
import os, sys, json, base64
from datetime import datetime, timezone
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Workspace root: override with CREDENTIAL_VAULT_WORKSPACE; defaults to
# the directory containing this script (the repo root when checked out).
WORKSPACE = Path(os.environ.get("CREDENTIAL_VAULT_WORKSPACE", Path(__file__).resolve().parent))
VAULT_DIR = WORKSPACE / ".vault"
VAULT_FILE = VAULT_DIR / "envs.enc"
SALT_FILE = VAULT_DIR / ".salt"

EXCLUDE_PATTERNS = [".env.example", ".env.template", ".env.sample", ".env.local.example"]

def get_key(password: str):
    VAULT_DIR.mkdir(parents=True, exist_ok=True)
    if not SALT_FILE.exists():
        salt = os.urandom(16)
        SALT_FILE.write_bytes(salt)
    else:
        salt = SALT_FILE.read_bytes()
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return Fernet(key)

def find_env_files():
    """Find all .env files excluding templates and examples."""
    env_files = []
    for p in WORKSPACE.rglob(".env*"):
        if not p.is_file():
            continue
        name = p.name.lower()
        # Skip explicit template/example patterns
        if any(name.endswith(ex.lower()) for ex in [".example", ".template", ".sample"]):
            continue
        # Skip .env files inside node_modules or venv
        if "node_modules" in str(p) or "/venv/" in str(p) or "/.venv/" in str(p):
            continue
        env_files.append(p)
    
    # Sort for deterministic ordering
    env_files.sort(key=lambda x: str(x.relative_to(WORKSPACE)))
    return env_files

def backup(password: str):
    env_files = find_env_files()
    if not env_files:
        print("⚪ No .env files found to backup")
        return 1
    
    print(f"🔍 Found {len(env_files)} .env files:")
    for f in env_files:
        print(f"   {f.relative_to(WORKSPACE)}")
    
    # Collect contents
    backup_data = {
        "version": 1,
        "created": datetime.now(timezone.utc).isoformat(),
        "files": []
    }
    
    for f in env_files:
        rel = str(f.relative_to(WORKSPACE))
        content = f.read_text()
        backup_data["files"].append({
            "path": rel,
            "size": len(content),
            "content": content
        })
    
    fernet = get_key(password)
    encrypted = fernet.encrypt(json.dumps(backup_data).encode())
    
    VAULT_DIR.mkdir(exist_ok=True)
    VAULT_FILE.write_bytes(encrypted)
    
    print(f"\n🔐 Encrypted {len(env_files)} .env files → {VAULT_FILE}")
    print(f"   Total size: {sum(f['size'] for f in backup_data['files'])} bytes")
    return 0

def restore(password: str, dry_run=False):
    if not VAULT_FILE.exists():
        print(f"🔴 No env vault found at {VAULT_FILE}")
        return 1
    
    fernet = get_key(password)
    try:
        decrypted = fernet.decrypt(VAULT_FILE.read_bytes())
        data = json.loads(decrypted)
    except Exception as e:
        print(f"🔴 Decryption failed: {e}")
        return 1
    
    print(f"📦 Vault contains {len(data['files'])} .env files (created {data.get('created', 'unknown')})")
    
    for entry in data["files"]:
        target = WORKSPACE / entry["path"]
        print(f"   {'[DRY-RUN]' if dry_run else ''} {entry['path']} ({entry['size']} bytes)")
        if not dry_run:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(entry["content"])
    
    if not dry_run:
        print(f"\n✅ Restored {len(data['files'])} files")
    return 0

def list_vault():
    if not VAULT_FILE.exists():
        print("⚪ No env vault found")
        return 0
    
    size = VAULT_FILE.stat().st_size
    print(f"📁 Env vault exists: {VAULT_FILE} ({size} bytes)")
    print("Use: python3 backup-envs.py restore")
    return 0

def verify(password: str):
    """Decrypt vault and verify a wallet address is present."""
    if not VAULT_FILE.exists():
        print("🔴 No env vault found")
        return 1
    
    fernet = get_key(password)
    try:
        decrypted = fernet.decrypt(VAULT_FILE.read_bytes())
        data = json.loads(decrypted)
    except Exception as e:
        print(f"🔴 Decryption failed: {e}")
        return 1
    
    wallet = os.environ.get("VERIFY_WALLET", "").lower()
    if not wallet:
        # Try to find any 0x address in the vault contents
        print("ℹ️  VERIFY_WALLET not set, searching for any 0x address...")
        found = []
        for entry in data["files"]:
            for line in entry["content"].splitlines():
                if "0x" in line.lower() and len(line) > 20:
                    # Extract potential addresses
                    import re
                    addrs = re.findall(r'0x[a-fA-F0-9]{40}', line)
                    found.extend(addrs)
        if found:
            print(f"✅ Found {len(found)} wallet address(es):")
            for a in set(found):
                print(f"   {a}")
            return 0
        else:
            print("⚪ No wallet addresses found in vault")
            return 1
    
    # Verify specific wallet
    found = False
    for entry in data["files"]:
        if wallet in entry["content"].lower():
            found = True
            print(f"✅ Wallet {wallet} found in {entry['path']}")
            break
    
    if not found:
        print(f"🔴 Wallet {wallet} NOT found in any .env file")
        return 1
    
    return 0

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    
    cmd = sys.argv[1]
    password = os.environ.get("VAULT_PASSWORD", "")
    
    if cmd in ("backup", "restore", "verify"):
        if not password:
            password = input("Vault password: ")
    
    if cmd == "backup":
        return backup(password)
    elif cmd == "restore":
        dry = "--dry-run" in sys.argv
        return restore(password, dry_run=dry)
    elif cmd == "list":
        return list_vault()
    elif cmd == "verify":
        return verify(password)
    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        return 1

if __name__ == "__main__":
    sys.exit(main())
