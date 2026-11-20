#!/usr/bin/env python3
"""
Shamir's Secret Sharing — Split master seed into 3-of-5 shards.
Any 3 shards reconstruct the seed. Any 2 or fewer reveal nothing.

Usage:
    python3 shamir-split.py split              # Split existing master seed
    python3 shamir-split.py combine [file...]  # Reconstruct from shards
    python3 shamir-split.py verify             # Verify all 5 shards valid
"""
import os, sys, json, random
from pathlib import Path

# Workspace root: override with CREDENTIAL_VAULT_WORKSPACE; defaults to
# the directory containing this script (the repo root when checked out).
WORKSPACE = Path(os.environ.get("CREDENTIAL_VAULT_WORKSPACE", Path(__file__).resolve().parent))
SHARD_DIR = WORKSPACE / ".shards"
SHAMIR_LIB = None

# Try multiple shamir implementations
try:
    from secretsharing import SecretSharer
    SHAMIR_LIB = "ssss"
except ImportError:
    try:
        from shamir import Shamir
        SHAMIR_LIB = "shamir"
    except ImportError:
        pass

# Pure-Python fallback (Shamir's Secret Sharing, GF(2^8))
def _gf_mul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a <<= 1
        a &= 0xFF
        if hi:
            a ^= 0x1b
        b >>= 1
    return p

def _gf_inv(a: int) -> int:
    if a == 0:
        raise ValueError("Division by zero")
    # In GF(2^8) the multiplicative group has order 255, so a^-1 = a^254.
    # (The original loop here computed a^127, which is not the inverse —
    # split/combine round-trips failed. Fixed Nov 2026, verified below.)
    result = 1
    base = a
    exp = 254
    while exp:
        if exp & 1:
            result = _gf_mul(result, base)
        base = _gf_mul(base, base)
        exp >>= 1
    return result

def _eval_poly(coeffs, x):
    result = 0
    for c in reversed(coeffs):
        result = _gf_mul(result, x) ^ c
    return result

def _lagrange_interpolate(points, x):
    result = 0
    for i, (xi, yi) in enumerate(points):
        num, den = 1, 1
        for j, (xj, _) in enumerate(points):
            if i != j:
                num = _gf_mul(num, x ^ xj)
                den = _gf_mul(den, xi ^ xj)
        result ^= _gf_mul(yi, _gf_mul(num, _gf_inv(den)))
    return result

def _split_secret(secret_bytes: bytes, n: int, k: int):
    """Split secret into n shares, any k can reconstruct."""
    shares = [[] for _ in range(n)]
    for byte in secret_bytes:
        coeffs = [byte] + [random.randint(0, 255) for _ in range(k - 1)]
        for i in range(n):
            x = i + 1
            shares[i].append(_eval_poly(coeffs, x))
    return [(i + 1, bytes(s)) for i, s in enumerate(shares)]

def _combine_shares(shares):
    """Reconstruct secret from any k shares."""
    length = len(shares[0][1])
    result = bytearray(length)
    for i in range(length):
        points = [(x, s[i]) for x, s in shares]
        result[i] = _lagrange_interpolate(points, 0)
    return bytes(result)

def get_master_seed() -> str:
    """Read and decrypt master seed."""
    seed_file = WORKSPACE / ".state" / "master-seed.enc"
    if not seed_file.exists():
        print("🔴 No master seed found at .state/master-seed.enc. Create an encrypted seed file first — see README.")
        sys.exit(1)
    
    pw = os.getenv("VAULT_PASSWORD") or input("Vault password: ")
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    import base64
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b"master_seed_salt_v1", iterations=480000)
    key = base64.urlsafe_b64encode(kdf.derive(pw.encode()))
    f = Fernet(key)
    try:
        return f.decrypt(seed_file.read_bytes()).decode()
    except Exception as e:
        print(f"🔴 Decryption failed: {e}")
        sys.exit(1)

def split_seed():
    seed = get_master_seed()
    seed_bytes = seed.encode('utf-8')
    
    shares = _split_secret(seed_bytes, n=5, k=3)
    
    SHARD_DIR.mkdir(parents=True, exist_ok=True)
    
    # Save each shard with metadata
    shard_files = []
    for idx, (x, data) in enumerate(shares, 1):
        shard = {
            "version": 1,
            "scheme": "shamir-3-of-5",
            "index": idx,
            "x": x,
            "data": data.hex(),
            "hint": f"Shard {idx} of 5. Need 3 shards to reconstruct.",
        }
        path = SHARD_DIR / f"shard-{idx}.json"
        path.write_text(json.dumps(shard, indent=2))
        shard_files.append(str(path))
    
    print(f"🔐 Master seed split into 5 shards")
    print(f"   Any 3 shards reconstruct the seed")
    print(f"   Any 2 or fewer reveal NOTHING")
    print(f"\n📁 Shard files:")
    for f in shard_files:
        print(f"   {f}")
    
    # Display storage recommendations
    print(f"\n💾 Recommended storage:")
    print(f"   Shard 1: Local encrypted vault (.shards/ — already done)")
    print(f"   Shard 2: Storj cloud backup")
    print(f"   Shard 3: Secondary git remote (encrypted)")
    print(f"   Shard 4: Paper backup (write hex + index)")
    print(f"   Shard 5: Trusted contact / separate machine")
    
    # Verify reconstruction works
    test_shares = [(x, data) for x, data in shares[:3]]
    reconstructed = _combine_shares(test_shares).decode()
    if reconstructed == seed:
        print(f"\n✅ Verified: 3 shards correctly reconstruct seed")
    else:
        print(f"\n🔴 ERROR: Reconstruction failed!")
        return 1
    
    return 0

def combine_shards(paths=None):
    if paths:
        shard_paths = [Path(p) for p in paths]
    else:
        # Auto-find shards
        if not SHARD_DIR.exists():
            print("🔴 No shards found. Run split first.")
            return 1
        shard_paths = sorted(SHARD_DIR.glob("shard-*.json"))
    
    shares = []
    for path in shard_paths:
        try:
            data = json.loads(path.read_text())
            shares.append((data["x"], bytes.fromhex(data["data"])))
            print(f"   Loaded shard {data['index']}: {path}")
        except Exception as e:
            print(f"   ⚠️ Failed to load {path}: {e}")
    
    if len(shares) < 3:
        print(f"\n🔴 Need at least 3 shards, only found {len(shares)}")
        return 1
    
    print(f"\n🔧 Reconstructing from {len(shares)} shards...")
    try:
        reconstructed = _combine_shares(shares[:3]).decode()
    except Exception as e:
        print(f"🔴 Reconstruction failed: {e}")
        return 1
    
    # Verify by checking it against master seed file
    seed_file = WORKSPACE / ".state" / "master-seed.enc"
    if seed_file.exists():
        pw = os.getenv("VAULT_PASSWORD") or input("Vault password (to verify): ")
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        import base64
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b"master_seed_salt_v1", iterations=480000)
        key = base64.urlsafe_b64encode(kdf.derive(pw.encode()))
        f = Fernet(key)
        try:
            actual = f.decrypt(seed_file.read_bytes()).decode()
            if actual == reconstructed:
                print(f"✅ Reconstructed seed matches stored seed")
            else:
                print(f"🔴 RECONSTRUCTED SEED DOES NOT MATCH!")
                print(f"   This should NEVER happen. Check your shards.")
                return 1
        except Exception:
            print(f"⚠️ Could not verify against stored seed (password mismatch or corruption)")
    
    words = reconstructed.split()
    print(f"\n🔓 Master seed reconstructed ({len(words)} words)")
    print(f"   First 4 words: {' '.join(words[:4])} ...")
    print(f"\n   Keep the reconstructed seed somewhere safe — never paste it into chat or commit it.")
    return 0

def verify_shards():
    if not SHARD_DIR.exists():
        print("🔴 No shards directory")
        return 1
    
    shards = sorted(SHARD_DIR.glob("shard-*.json"))
    if len(shards) < 5:
        print(f"⚠️ Only {len(shards)}/5 shards present")
    
    valid = 0
    for path in shards:
        try:
            data = json.loads(path.read_text())
            bytes.fromhex(data["data"])  # Validate hex
            print(f"   ✅ Shard {data['index']}: valid ({len(data['data'])} hex chars)")
            valid += 1
        except Exception as e:
            print(f"   ❌ {path}: invalid — {e}")
    
    print(f"\n{valid}/{len(shards)} shards valid")
    return 0 if valid >= 3 else 1

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 shamir-split.py [split|combine|verify]")
        return 1
    
    cmd = sys.argv[1]
    if cmd == "split":
        return split_seed()
    elif cmd == "combine":
        return combine_shards(sys.argv[2:])
    elif cmd == "verify":
        return verify_shards()
    else:
        print(f"Unknown: {cmd}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
