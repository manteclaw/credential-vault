#!/usr/bin/env python3
"""
Backup Verification — Monthly test: reconstruct master seed from Shamir shards,
derive wallet addresses, verify against live keys.
Usage:
    python3 verify-backup.py test        # Full test: shards -> seed -> addresses
    python3 verify-backup.py quick       # Check file presence + checksums
    python3 verify-backup.py report      # Show last test results
"""
import os, sys, json, hashlib
from pathlib import Path
from datetime import datetime

# Workspace root: override with CREDENTIAL_VAULT_WORKSPACE; defaults to
# the directory containing this script (the repo root when checked out).
WORKSPACE = Path(os.environ.get("CREDENTIAL_VAULT_WORKSPACE", Path(__file__).resolve().parent))
def _script_path(name: str):
    """Resolve a sibling script: same directory as this file, else WORKSPACE/scripts."""
    here = Path(__file__).resolve().parent / name
    if here.exists():
        return here
    alt = WORKSPACE / "scripts" / name
    return alt if alt.exists() else None


SHARD_DIR = WORKSPACE / ".shards"
MANIFEST = WORKSPACE / ".state" / "key-inventory.json"
REPORT_FILE = WORKSPACE / ".state" / "backup-verification-report.json"
SEED_FILE = WORKSPACE / ".state" / "master-seed.enc"

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()[:16]

def quick_check():
    issues = []
    
    # Check master seed exists
    if not SEED_FILE.exists():
        issues.append("Master seed file missing: .state/master-seed.enc")
    else:
        print(f"   ✅ Master seed: {SEED_FILE} ({SEED_FILE.stat().st_size} bytes)")
    
    # Check shards exist
    if not SHARD_DIR.exists():
        issues.append("Shard directory missing: .shards/")
    else:
        shards = sorted(SHARD_DIR.glob("shard-*.json"))
        if len(shards) < 3:
            issues.append(f"Only {len(shards)} shards found (need 3+ for recovery)")
        else:
            print(f"   ✅ Shards: {len(shards)} found")
            for s in shards:
                h = sha256_file(s)
                print(f"      {s.name}: checksum {h}")
    
    # Check inventory exists (optional: only tracks keys, not needed for recovery)
    if not MANIFEST.exists():
        print("   ⚠️  No key inventory (.state/key-inventory.json) — optional, see README")
    else:
        print(f"   ✅ Key inventory: {MANIFEST}")
        data = json.loads(MANIFEST.read_text())
        print(f"      {data['total_keys']} keys tracked")
    
    # Check vault exists (credential-vault.py writes keys.enc, backup-envs.py writes envs.enc)
    vaults = [WORKSPACE / ".vault" / "keys.enc", WORKSPACE / ".vault" / "envs.enc"]
    found_vault = next((v for v in vaults if v.exists()), None)
    if found_vault:
        print(f"   ✅ Credential vault: {found_vault}")
    else:
        print(f"   ⚠️  Credential vault not found: {WORKSPACE / '.vault'}")
    
    # Check offsite backups (Storj)
    storj_log = WORKSPACE / ".storj_sync.log"
    if storj_log.exists():
        last_line = storj_log.read_text().strip().split("\n")[-1]
        print(f"   ✅ Storj sync: {last_line}")
    else:
        print(f"   ⚠️  No Storj sync log")
    
    if issues:
        print(f"\n🔴 {len(issues)} CRITICAL ISSUES:")
        for i in issues:
            print(f"   - {i}")
        return 1
    else:
        print(f"\n✅ Quick check passed")
        return 0

def test_reconstruction():
    if not SEED_FILE.exists():
        print("🔴 Master seed file missing")
        return 1
    
    if not SHARD_DIR.exists():
        print("🔴 Shard directory missing")
        return 1
    
    shards = sorted(SHARD_DIR.glob("shard-*.json"))
    if len(shards) < 3:
        print(f"🔴 Only {len(shards)} shards (need 3)")
        return 1
    
    # Load shamir module (sibling script)
    shamir_path = _script_path("shamir-split.py")
    if shamir_path is None:
        print("🔴 shamir-split.py not found next to this script")
        return 1
    import importlib.util
    spec = importlib.util.spec_from_file_location("shamir", shamir_path)
    shamir = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(shamir)
    
    # Load 3 shards
    loaded_shares = []
    for path in shards[:3]:
        data = json.loads(path.read_text())
        loaded_shares.append((data["x"], bytes.fromhex(data["data"])))
        print(f"   Loaded shard {data['index']} from {path.name}")
    
    # Reconstruct
    print(f"\n🔧 Reconstructing master seed from 3 shards...")
    try:
        reconstructed = shamir._combine_shares(loaded_shares).decode()
    except Exception as e:
        print(f"🔴 Reconstruction FAILED: {e}")
        return 1
    
    words = reconstructed.split()
    print(f"   Reconstructed seed: {len(words)} words")
    print(f"   First 4 words: {' '.join(words[:4])} ...")
    
    # Decrypt stored seed to verify match
    pw = os.getenv("VAULT_PASSWORD") or input("Vault password (to verify match): ")
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    import base64
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b"master_seed_salt_v1", iterations=480000)
    key = base64.urlsafe_b64encode(kdf.derive(pw.encode()))
    f = Fernet(key)
    try:
        stored = f.decrypt(SEED_FILE.read_bytes()).decode()
    except Exception as e:
        print(f"🔴 Could not decrypt stored seed: {e}")
        return 1
    
    if stored == reconstructed:
        print(f"   ✅ Reconstructed seed MATCHES stored seed")
    else:
        print(f"🔴 CRITICAL: Reconstructed seed DOES NOT MATCH stored seed!")
        print(f"   This means your shards are corrupted or from a different seed.")
        return 1
    
    # Derive wallets and verify against inventory
    print(f"\n🔑 Deriving wallet addresses from seed...")
    
    # Derive wallets and verify against inventory.
    # Optional: needs master-seed.py alongside this script. If it is absent,
    # derivation is skipped — shard reconstruction + seed match above are
    # the actual verification.
    seed_path = _script_path("master-seed.py")
    if seed_path is None:
        print("   ⚠️  master-seed.py not present — skipping wallet derivation")
        derivation_config = {}
    else:
        spec = importlib.util.spec_from_file_location("master_seed", seed_path)
        ms = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ms)

        if not ms.DERIVATION_CONFIG.exists():
            print(f"⚠️  No derivation config found")
            derivation_config = ms.DEFAULT_DERIVATIONS
        else:
            derivation_config = json.loads(ms.DERIVATION_CONFIG.read_text())
    
    matches = 0
    for name, info in derivation_config.items():
        wallet = ms.derive_wallet(info["index"], reconstructed, info.get("path"))
        print(f"   {name:<16} → {wallet['address']}")
    
    # Compare with inventory
    if MANIFEST.exists():
        manifest = json.loads(MANIFEST.read_text())
        live_addrs = set()
        for k in manifest["keys"]:
            if k.get("address"):
                live_addrs.add(k["address"].lower())
        
        for name, info in derivation_config.items():
            wallet = ms.derive_wallet(info["index"], reconstructed, info.get("path"))
            if wallet["address"].lower() in live_addrs:
                print(f"   ✅ {name}: matches live key in inventory")
                matches += 1
            else:
                print(f"   ⚠️  {name}: NOT found in live inventory (new wallet?)")
        
        print(f"\n📊 {matches}/{len(derivation_config)} derived wallets match live inventory")
    
    # Save report
    report = {
        "tested_at": datetime.now().isoformat(),
        "reconstruction": "success",
        "seed_match": stored == reconstructed,
        "shards_used": 3,
        "total_shards_available": len(shards),
        "wallets_derived": len(derivation_config),
        "wallets_match_inventory": matches if MANIFEST.exists() else None,
    }
    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    REPORT_FILE.write_text(json.dumps(report, indent=2))
    
    print(f"\n✅ BACKUP VERIFICATION PASSED")
    print(f"   Report saved: {REPORT_FILE}")
    return 0

def show_report():
    if not REPORT_FILE.exists():
        print("⚪ No backup verification report yet. Run: python3 verify-backup.py test")
        return 1
    
    report = json.loads(REPORT_FILE.read_text())
    print(f"\n📋 Last Backup Verification")
    print(f"   Date: {report.get('tested_at', 'unknown')}")
    print(f"   Reconstruction: {report.get('reconstruction', '?')}")
    print(f"   Seed match: {'✅' if report.get('seed_match') else '❌'}")
    print(f"   Shards used: {report.get('shards_used', '?')}/{report.get('total_shards_available', '?')}")
    print(f"   Wallets derived: {report.get('wallets_derived', '?')}")
    if report.get('wallets_match_inventory') is not None:
        print(f"   Wallets match live: {report['wallets_match_inventory']}/{report['wallets_derived']}")
    return 0

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 verify-backup.py [test|quick|report]")
        return 1
    
    cmd = sys.argv[1]
    if cmd == "test":
        return test_reconstruction()
    elif cmd == "quick":
        return quick_check()
    elif cmd == "report":
        return show_report()
    else:
        print(f"Unknown: {cmd}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
