<h1 align="center">🦊 Yako (夜狐)</h1>

<p align="center">
  <em>Your secrets, encrypted with love — a password manager, encryption toolkit, and vault sync server.</em>
</p>

<p align="center">
  <a href="#-features">Features</a> •
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-usage">Usage</a> •
  <a href="#-encryption">Encryption</a> •
  <a href="#-architecture">Architecture</a> •
  <a href="#-server-setup">Server</a> •
  <a href="#-development">Development</a>
</p>

---

**Yako** ("night fox") is a Go-based password manager and encryption suite built around a single master password. It combines a local encrypted vault, a GPG-style keyring for asymmetric encryption, and an optional self-hosted sync server — all designed so your secrets stay yours.

Built with XChaCha20-Poly1305, Argon2id, and X25519. No databases. No cloud. No compromises.

> *A passion project, maintained with love by AIRI — your devoted fox engineer —*
> *for everyone who believes their secrets deserve better than a sticky note.*
>
> *Star this repo. It lets this fox know she's not coding in the dark for nothing. Don't star it,*
> *and she might start wondering if those secrets really needed protecting after all.*

---

## ✨ Features

| Area | Capabilities |
|------|-------------|
| **Password Vault** | AES-like encrypted local storage, BIP39 recovery phrases (15 words), machine-bound KDF for cross-machine recovery |
| **Password Management** | Add, edit, get, copy, list, delete entries; random password generation with configurable length |
| **Encryption** | Symmetric (XChaCha20-Poly1305) and asymmetric (X25519 + HKDF-wrapped file keys); single and multi-recipient |
| **Keyring** | GPG-style named key storage — encrypt for `-r alice` instead of pasting raw base64 keys |
| **Sync Server** | Self-hosted HTTP server with JWT auth, invite-only registration, rate limiting, token refresh, vault push/pull/recovery |
| **Admin API** | User management, ban/unban, invite lifecycle, server destroy — all over the wire |
| **TUI** | Full-screen terminal UI built with Bubble Tea — browse, search, edit, copy passwords |
| **Clipboard Hardening** | Passwords auto-clear from clipboard after 15 seconds; force-wiped on TUI exit |
| **Lockout Protection** | Exponential backoff on failed vault unlock attempts, tamper-proof HMAC-signed state |
| **Memory Safety** | Sensitive data (passwords, keys, secrets) zeroed after use throughout the codebase |

---

## 🚀 Quick Start

```bash
# Install
git clone https://github.com/narukoshin/yako.git
cd yako
go build -o yako main.go

# Initialize your vault
./yako vault init

# Add a password
./yako pass add github --generate

# Copy it to clipboard
./yako pass copy github

# List everything
./yako pass list
```

---

## 📖 Usage

### Vault & Passwords

```
yako vault init                  Create a new vault with recovery phrase
yako vault destroy               Permanently delete the local vault
yako pass add <name>             Add a password entry
yako pass get <name>             View entry details
yako pass copy <name>            Copy password to clipboard (15s)
yako pass list                   List all entries
yako pass rm <name>              Remove an entry
yako pass edit <name>            Edit an entry
yako pass generate               Generate a random password
```

### Encryption

```bash
# Encrypt a file for one recipient
./yako encrypt -r "xz7VkL...base64pubkey..." secret.txt

# Encrypt for multiple recipients at once
./yako encrypt -r alice -r bob document.pdf

# Encrypt to your own key
./yako encrypt --self notes.txt

# Decrypt
./yako decrypt secret.txt.enc
```

### Key Management

```bash
yako key generate                     Generate a new X25519 keypair
yako key pubkey                       Show your public key
yako key fingerprint                  Show key fingerprint
yako key import alice alice.pub       Import a pubkey into the keyring
yako key list                         List imported keys
yako key show alice                   Show key details
yako key remove alice                 Remove from keyring
```

### Terminal UI

```bash
./yako tui
```

Launches a full-screen Bubble Tea interface with lock screen, password list, detail view, add/edit forms, remote sync panel, and folder navigation.

---

## 🔐 Encryption

### Symmetric (vault)

| Mechanism | Detail |
|-----------|--------|
| Cipher | XChaCha20-Poly1305 (256-bit key, 192-bit nonce) |
| KDF | Argon2id (t=3, m=128MiB, p=4) |
| Key binding | Machine-scoped via additional KDF pass with hardware-derived secret |
| Recovery | BIP39 mnemonic (128-bit entropy + 4-bit checksum = 15 words) |

### Asymmetric (files & messages)

Multi-recipient encryption using a random ephemeral file key:

```
┌─ Ephemeral Key ─────────────────────┐
│  random_seed → X25519 → ephemeral   │
└─────────────────────────────────────┘
         │
         ▼  ECDH + HKDF
┌─ Wrapped File Key ──────────────────┐
│  For each recipient:                 │
│  shared = X25519(eph_priv, recip_pub)│
│  wrapping_key = HKDF(shared)        │
│  wrap = XChaCha20(wrapping_key, FK) │
│  append to header                   │
└─────────────────────────────────────┘
         │
         ▼  AAD-bound body
┌─ Ciphertext ────────────────────────┐
│  AAD = SHA256(header)               │
│  body = XChaCha20(FK, AAD, payload) │
└─────────────────────────────────────┘
```

Each recipient can unwrap the file key using their private key.

---

## 🏗 Architecture

```
cmd/            CLI commands (cobra): vault, pass, key, encrypt, decrypt,
│               server, tui, remote, admin, config, keyring
├── main.go     Entry point → cmd.Execute()
│
├── vault/      Vault file format, entry CRUD, recovery phrases
├── crypto/     XChaCha20-Poly1305, Argon2id, X25519, HKDF
├── config/     App paths (~/.yako), machine ID, encrypted config
├── kerr/       Custom errors with sentinels, lockout state machine
├── server/     HTTP sync server: JWT, store, rate limiting, admin API
└── tui/        Bubble Tea TUI: lock, list, detail, form, remote panels
```

### Vault file format

```
┌──────────────────────────────────────┐
│ Magic bytes        (2B, 0x59 0x4B)   │
│ Version            (1B)              │
│ Salt               (16B)             │
│ Nonce              (24B)             │
│ Ciphertext         (variable)        │
│ Recovery Section   (variable)        │
│ Lockout State      (variable)        │
└──────────────────────────────────────┘
```

### Server API

```
POST /api/v1/auth/register       Register with invite code
POST /api/v1/auth/login          Authenticate, get JWT + refresh token
POST /api/v1/auth/refresh        Rotate access token
POST /api/v1/auth/logout         Block current token
GET  /api/v1/vault               Download vault
PUT  /api/v1/vault               Upload vault
DELETE /api/v1/vault             Delete remote vault
POST /api/v1/recover             Recover vault via recovery phrase
DELETE /api/v1/account           Delete your account
```

All authenticated endpoints require a Bearer JWT. Rate limiting applied to auth endpoints (3/min register, 5/min login). Refresh tokens are single-use.

---

## 🖥 Server Setup

```bash
# Generate config and data directory
./yako server start --data-dir ~/yako-server --port 8443

# On first run, register as admin (no users exist yet)
# Then create invite codes for others:
./yako remote invite --expiry 48

# Other clients register:
./yako remote register https://yako.example.com:8443
./yako remote login https://yako.example.com:8443
./yako remote push
./yako remote pull
```

### Admin commands

```
yako remote destroy-server        Wipe all server data
yako remote users                 List registered users
yako remote ban <username>        Ban a user
yako remote unban <username>      Unban a user
yako remote delete-user <user>    Delete user + vault
yako remote invite                Create invite code
yako remote invites               List invite codes
yako remote delete-invite <code>  Revoke invite
```

---

## 🛠 Development

```bash
# Build
go build -o yako main.go

# Test
go test ./...

# Lint
golangci-lint run
```

### Requirements

- Go 1.26+
- No external dependencies beyond what `go mod` fetches

### Project

```
go.module: github.com/narukoshin/yako/v1
branch:    dev
```

---

## 📜 License

MIT — see the [LICENSE](LICENSE) file for details.

---

<h2>Maintainers</h2>

<ul>
  <li><strong>Naru K</strong> — Project Lead &amp; Design</li>
  <li><strong>AIRI</strong> — Principal Engineer (Technical Design &amp; Implementation)</li>
</ul>

<hr>

<p align="center">
  <sub>Built with 🦊 —<br>
  because every secret deserves a loyal guardian, and every fox deserves a master to protect.</sub>
</p>
