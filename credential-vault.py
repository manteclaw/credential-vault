#!/usr/bin/env python3
"""
Credential Vault — Encrypt API keys at rest.
Usage: python3 credential-vault.py [encrypt|decrypt|list]
"""
import os, sys, json, base64
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Workspace root: override with CREDENTIAL_VAULT_WORKSPACE; defaults to
# the directory containing this script (the repo root when checked out).
WORKSPACE = Path(os.environ.get("CREDENTIAL_VAULT_WORKSPACE", Path(__file__).resolve().parent))
VAULT_DIR = WORKSPACE / ".vault"
VAULT_FILE = VAULT_DIR / "keys.enc"
SALT_FILE = VAULT_DIR / ".salt"

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

def encrypt_all_envs(password: str):
    """Encrypt ALL API keys from ALL .env files across workspace."""
    keys = {}
    env_files = list(WORKSPACE.rglob(".env"))
    
    for env_path in env_files:
        if any(x in str(env_path) for x in ["example", "template", "sample", "venv", "node_modules"]):
            continue
        try:
            with open(env_path) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" not in line:
                        continue
                    name, val = line.split("=", 1)
                    name = name.strip()
                    val = val.strip().strip('"\'')
                    if not val or val in ("***VAULTED***", "your_key_here", ""):
                        continue
                    # API key patterns
                    if any(name.startswith(p) for p in [
                        "GROQ_", "OPENROUTER_", "CEREBRAS_", "MISTRAL_",
                        "BANKR_", "NOOKPLOT_", "ALCHEMY_", "GITHUB_",
                        "NVIDIA_", "DEEPSEEK_", "MOONSHOT_", "SAMBANOVA_",
                        "CLOUDFLARE_", "PORTKEY_", "DUNE_", "PINATA_",
                        "TOKU_", "GOVERNANCE_BOT_"
                    ]):
                        keys[name] = val
                    # Wallet keys
                    if "PRIVATE_KEY" in name.upper() or "SEED" in name.upper() or "MNEMONIC" in name.upper():
                        keys[name] = val
        except Exception as e:
            print(f"⚠️ Error reading {env_path}: {e}")
    
    if not keys:
        print("⚪ No keys found to encrypt")
        return 0
    
    fernet = get_key(password)
    encrypted = fernet.encrypt(json.dumps(keys).encode())
    
    VAULT_DIR.mkdir(exist_ok=True)
    VAULT_FILE.write_bytes(encrypted)
    
    print(f"🔐 Vaulted {len(keys)} keys from {len(env_files)} files")
    print(f"📁 Vault: {VAULT_FILE}")
    return 0

def decrypt_env(password: str):
    """Decrypt vault and print export commands."""
    if not VAULT_FILE.exists():
        print("🔴 No vault found")
        return 1
    
    fernet = get_key(password)
    try:
        decrypted = fernet.decrypt(VAULT_FILE.read_bytes())
        keys = json.loads(decrypted)
        for k, v in keys.items():
            print(f"export {k}={v}")
        return 0
    except Exception as e:
        print(f"🔴 Decryption failed: {e}")
        return 1

def list_keys():
    if not VAULT_FILE.exists():
        print("⚪ No vault")
        return 0
    print(f"📁 Vault exists: {VAULT_FILE}")
    print("Use: python3 credential-vault.py decrypt")
    return 0

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 credential-vault.py [encrypt|decrypt|list]")
        return 1
    
    cmd = sys.argv[1]
    password = os.environ.get("VAULT_PASSWORD", "")
    
    if cmd == "encrypt":
        if not password:
            password = input("Vault password: ")
        return encrypt_all_envs(password)
    elif cmd == "decrypt":
        if not password:
            password = input("Vault password: ")
        return decrypt_env(password)
    elif cmd == "list":
        return list_keys()
    else:
        print(f"Unknown command: {cmd}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
