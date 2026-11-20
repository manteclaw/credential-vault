#!/usr/bin/env python3
"""
Vault Watcher — Monitor .env files for changes and auto-re-encrypt to credential vault.
Usage:
    python3 vault-watcher.py           # Single check
    python3 vault-watcher.py daemon  # Background daemon (run via cron)
    python3 vault-watcher.py install-cron  # Add to crontab
"""
import os, sys, hashlib, json, time
from pathlib import Path
from datetime import datetime

# Workspace root: override with CREDENTIAL_VAULT_WORKSPACE; defaults to
# the directory containing this script (the repo root when checked out).
WORKSPACE = Path(os.environ.get("CREDENTIAL_VAULT_WORKSPACE", Path(__file__).resolve().parent))
STATE_FILE = WORKSPACE / ".state" / "vault-watcher-state.json"
# credential-vault.py writes keys.enc; watch that file.
VAULT_FILE = WORKSPACE / ".vault" / "keys.enc"

def get_env_files() -> list[Path]:
    """Find all .env files excluding examples/templates."""
    files = []
    for env_file in WORKSPACE.rglob(".env"):
        path_str = str(env_file)
        if any(x in path_str for x in ["example", "template", "sample", "venv", "node_modules", "__pycache__"]):
            continue
        files.append(env_file)
    return files

def compute_hash(filepath: Path) -> str:
    """Hash file contents for change detection."""
    try:
        return hashlib.sha256(filepath.read_bytes()).hexdigest()[:16]
    except Exception:
        return ""

def load_state() -> dict:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {"files": {}, "last_check": None, "last_vault": None}

def save_state(state: dict):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2))

def trigger_vault_encrypt():
    """Run credential vault encryption."""
    import subprocess
    pw = os.getenv("VAULT_PASSWORD")
    if not pw:
        print("⚠️ VAULT_PASSWORD not set, skipping auto-encrypt")
        return False
    
    vault_script = Path(__file__).resolve().parent / "credential-vault.py"
    if not vault_script.exists():
        alt = WORKSPACE / "scripts" / "credential-vault.py"
        vault_script = alt if alt.exists() else vault_script
    cmd = [sys.executable, str(vault_script), "encrypt"]
    env = os.environ.copy()
    env["VAULT_PASSWORD"] = pw
    
    try:
        result = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            return True
        else:
            print(f"⚠️ Vault encrypt failed: {result.stderr[:200]}")
            return False
    except Exception as e:
        print(f"⚠️ Vault encrypt error: {e}")
        return False

def check_changes():
    state = load_state()
    files = get_env_files()
    changed = False
    new_hashes = {}
    
    for f in files:
        h = compute_hash(f)
        rel = str(f.relative_to(WORKSPACE))
        old = state["files"].get(rel)
        if old != h:
            if old is not None:
                print(f"   📝 Changed: {rel}")
            changed = True
        new_hashes[rel] = h
    
    # Detect deleted files
    for old_file in state["files"]:
        if old_file not in new_hashes:
            print(f"   🗑️  Deleted: {old_file}")
            changed = True
    
    if not changed:
        print(f"✅ No .env changes since last check ({state.get('last_check', 'never')})")
        return 0
    
    print(f"🔔 {len(files)} .env files tracked, changes detected")
    
    # Update state BEFORE encrypt to avoid loops
    state["files"] = new_hashes
    state["last_check"] = datetime.now().isoformat()
    save_state(state)
    
    # Trigger vault encrypt
    print(f"🔐 Triggering vault re-encryption...")
    if trigger_vault_encrypt():
        state["last_vault"] = datetime.now().isoformat()
        save_state(state)
        print(f"✅ Vault updated: {VAULT_FILE}")
    else:
        print(f"⚠️ Vault update failed — keys NOT backed up")
        return 1
    
    return 0

def install_cron():
    """Add vault-watcher to crontab."""
    import subprocess
    cron_line = f"*/5 * * * * cd {WORKSPACE} && python3 vault-watcher.py daemon >> {WORKSPACE}/.state/vault-watcher.log 2>&1"
    
    # Check if already installed
    result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
    if "vault-watcher" in result.stdout:
        print("✅ Already in crontab")
        return 0
    
    new_cron = result.stdout.strip() + "\n# Auto-vault watcher — re-encrypts .env changes\n" + cron_line + "\n"
    
    proc = subprocess.Popen(["crontab", "-"], stdin=subprocess.PIPE, text=True)
    proc.communicate(new_cron)
    
    if proc.returncode == 0:
        print("✅ Cron installed: checks every 5 minutes")
    else:
        print("🔴 Cron install failed")
        return 1
    return 0

def daemon_mode():
    """Run once and exit — intended for cron invocation."""
    return check_changes()

def main():
    if len(sys.argv) < 2:
        return check_changes()
    
    cmd = sys.argv[1]
    if cmd == "daemon":
        return daemon_mode()
    elif cmd == "install-cron":
        return install_cron()
    elif cmd == "force":
        # Force re-encrypt regardless of changes
        state = load_state()
        files = get_env_files()
        state["files"] = {str(f.relative_to(WORKSPACE)): compute_hash(f) for f in files}
        state["last_check"] = datetime.now().isoformat()
        save_state(state)
        trigger_vault_encrypt()
        return 0
    else:
        print(f"Unknown: {cmd}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
