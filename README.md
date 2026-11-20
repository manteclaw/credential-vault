# credential-vault

At-rest encryption for `.env` secrets, plus a tested 3-of-5 Shamir seed-backup scheme — no cloud vault, no third-party service. Your keys stay on your disk, encrypted with a password only you know.

## ⚠️ Read this first — unaudited, security-critical code

**This code is unaudited and it handles seed material. Review it before trusting it with real seeds. Treat it as educational, not audited.** It was written for one operator's personal setup and published so others can read, adapt, and improve it — not as a guarantee that your secrets are safe. If you use it for real funds:

- Read every script before running it. They are short (~1,000 lines total).
- Test the full round-trip (encrypt → decrypt → reconstruct) with throwaway values first.
- Keep shards in genuinely separate places. Three shards in one laptop is one shard.
- Know the limitations below before you rely on it.

## What it does

| Script | Role |
|---|---|
| `credential-vault.py` | Encrypts API keys from all `.env` files in your workspace into a Fernet vault (`.vault/keys.enc` + salt). Key derived from your password via PBKDF2-HMAC-SHA256, 480,000 iterations. Commands: `encrypt`, `decrypt`, `list`. |
| `backup-envs.py` | Backs up whole `.env` files (not just extracted keys) into an encrypted vault (`.vault/envs.enc`). Commands: `backup`, `restore` (with `--dry-run`), `list`, `verify`. |
| `shamir-split.py` | Splits a master seed into 5 Shamir shards — any 3 reconstruct it, any 2 or fewer reveal nothing. Pure-Python GF(2^8) implementation, no library required. Commands: `split`, `combine [files...]`, `verify`. |
| `verify-backup.py` | Monthly backup test: reconstructs the seed from 3 shards, checks it matches the stored seed, and (if you provide derivation tooling) derives wallet addresses and checks them against your key inventory. Commands: `test`, `quick`, `report`. |
| `vault-watcher.py` | Watches `.env` files for changes and re-encrypts the vault automatically. Run once, as a daemon, or install as a cron job (`install-cron`, every 5 minutes). |

No vault, shard, or seed content ships with this repo. The `.gitignore` excludes `.vault/`, `.shards/`, `.state/`, `*.enc`, and `.env` by default.

## Setup

```bash
git clone https://github.com/manteclaw/credential-vault.git
cd credential-vault
python3 -m pip install -r requirements.txt
cp .env.example .env   # then set VAULT_PASSWORD — or leave unset and be prompted
```

Only hard dependency is `cryptography`. `shamir-split.py` works without any Shamir library (pure-Python fallback). `eth-account` is only needed if you bring your own seed-derivation script (see below).

By default the scripts operate on the directory they live in. Point them at a different workspace with:

```bash
export CREDENTIAL_VAULT_WORKSPACE=/path/to/your/workspace
```

## Usage

```bash
# Vault your API keys
python3 credential-vault.py encrypt
python3 credential-vault.py decrypt   # prints export commands
python3 credential-vault.py list

# Back up whole .env files
python3 backup-envs.py backup
python3 backup-envs.py restore --dry-run
python3 backup-envs.py verify        # checks a wallet address is in the vault

# Split a seed into 3-of-5 shards (needs an encrypted seed at .state/master-seed.enc)
python3 shamir-split.py split
python3 shamir-split.py combine shard-1.json shard-3.json shard-5.json
python3 shamir-split.py verify

# Monthly backup test
python3 verify-backup.py quick       # file presence + checksums
python3 verify-backup.py test        # full reconstruction test
python3 verify-backup.py report      # last test results

# Watch .env files and auto re-encrypt
python3 vault-watcher.py             # single check
python3 vault-watcher.py install-cron
```

### The seed file

`shamir-split.py` and `verify-backup.py` expect an encrypted master seed at `.state/master-seed.enc` (Fernet-encrypted with your vault password). This repo deliberately does **not** include the script that creates that file — generating and storing a master seed is the part you should do yourself, deliberately, after reading the code. Until that file exists, `split`/`test` will tell you it is missing and exit.

Likewise, `verify-backup.py test` derives wallet addresses only if a `master-seed.py` with derivation helpers sits next to it; without one it verifies shard reconstruction and the seed match and skips derivation, saying so.

## Known limitations (honest list)

- **Unaudited.** No third party has reviewed this code. The Shamir implementation is a hand-rolled GF(2^8) fallback — correct by construction and self-tested (split → combine → compare), but not a vetted library.
- **Fixed salt in the seed encryption.** The master-seed decryption uses a fixed salt (`master_seed_salt_v1`). A per-file random salt would be better; this is a known weakness, kept for compatibility with the original setup.
- **`random` is not cryptographic.** Shard coefficients use Python's `random` module, not `secrets`. For a stronger guarantee, swap `random.randint` for `secrets.randbelow` in `shamir-split.py`.
- **Vault password handling.** The password comes from `VAULT_PASSWORD` or an interactive prompt. It is never written to disk by these scripts — but your shell history and process list can leak env vars, so prefer the prompt.
- **`decrypt` prints secrets to stdout.** That is the point of the command, but don't pipe it into logs or screenshots.
- **`restore` overwrites files.** `backup-envs.py restore` writes `.env` files back to their recorded paths. Use `--dry-run` first.
- **No forward secrecy or rotation.** Re-encrypting with a new password does not re-encrypt old copies you may have backed up elsewhere. Old vault files stay decryptable with the old password until you delete them.

## License

MIT — see `LICENSE`.
