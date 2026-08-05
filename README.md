![MIT License](https://img.shields.io/badge/License-MIT-green.svg)
![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS%20%7C%20Termux-lightgrey.svg)

# pmgr — Secure CLI Password Manager

**A single-user, file-based, encrypted password manager for the terminal.**
Works on Termux (Android), Windows, macOS, and Linux.

---

## 1. Overview

`pmgr` is a command-line tool for storing and retrieving passwords securely on your own device. There is no server, no cloud account, and no telemetry — everything lives in one encrypted file on your local filesystem, protected by a single master password that only you know.

It was built for people who want the convenience of a password manager without trusting a third-party company with their credentials, and who are comfortable working in a terminal.

**Design goals:**
- Real, industry-standard encryption — not "security through obscurity"
- Single file, easy to back up or move between devices
- No plaintext ever touches disk
- Works identically across Termux, Windows, macOS, and Linux
- Fast and pleasant to use, not just secure

---

## 2. How It Works

### 2.1 The core idea

Your vault is a single JSON file (`~/.pmgr/vault.dat`) containing:
- A random **salt**
- The **KDF iteration count** used
- One **encrypted blob** — your entire password vault, encrypted as a whole

Nothing in that file is readable without your master password. Not the entry names, not the usernames, not the passwords — none of it.

### 2.2 Turning your password into an encryption key

Computers can't encrypt data with a password directly — they need a fixed-length cryptographic key. `pmgr` derives that key from your master password using **PBKDF2-HMAC-SHA256** with **600,000 iterations**, the iteration count currently recommended by OWASP (2023 guidance) for this algorithm.

```
master password + random salt  →  [PBKDF2-HMAC-SHA256 × 600,000]  →  32-byte key
```

Two things make this resistant to attack:
- **The salt** is random and unique per vault, so pre-computed ("rainbow table") attacks don't work — an attacker has to attack your vault specifically.
- **The iteration count** deliberately slows down key derivation. A single guess takes a noticeable fraction of a second, which means brute-forcing millions of password guesses against your vault file becomes impractical, even offline.

### 2.3 Encrypting the vault

Once the key is derived, the entire vault (all entries, as one JSON object) is encrypted using **Fernet**, which combines:
- **AES-128 in CBC mode** for confidentiality (scrambling the data)
- **HMAC-SHA256** for authentication (detecting tampering)

This means if even a single byte of the encrypted file is altered — corrupted, or tampered with — decryption fails outright instead of silently returning corrupted data.

### 2.4 What happens when you run a command

```
 You type master password
        │
        ▼
 PBKDF2 re-derives the same key (using the stored salt)
        │
        ▼
 Fernet attempts to decrypt the vault
        │
   ┌────┴────┐
   ▼         ▼
 Success   Failure → "Wrong master password" (exit, nothing shown)
   │
   ▼
 Vault loaded into memory only for this command
        │
        ▼
 Command runs (add/get/list/edit/remove)
        │
        ▼
 If vault changed, it's re-encrypted and written back to disk
        │
        ▼
 Everything cleared from memory when the command exits
```

Your master password is **typed fresh every time** you run a command. It is never written to disk, never cached, never logged.

### 2.5 What's stored on disk vs. what's not

| Stored on disk (encrypted) | Never stored anywhere |
|---|---|
| Entry names, usernames, passwords, URLs, notes | Your master password |
| Salt + iteration count (needed to re-derive the key) | Derived encryption key (memory only, per-session) |

If you forget your master password, there is **no recovery mechanism** — by design. Anyone who could recover it (including the tool itself) would also be a way for an attacker to get in.

### 2.6 File permissions

On Unix-like systems (Linux, macOS, Termux), the vault file is set to `600` permissions — readable and writable only by your own user account, not other users on the same machine. Windows uses its own file ACL model, which already restricts access to your user profile folder by default.

---

## 3. Features

### 🔐 Security
- AES-128 + HMAC-SHA256 authenticated encryption (Fernet)
- PBKDF2-HMAC-SHA256, 600,000 iterations, random per-vault salt
- Master password never stored or logged
- Vault file is a single opaque encrypted blob — tampering is detected, not silently ignored
- Owner-only file permissions on Unix systems

### 🗂 Vault management
- `init` — create a new vault with a chosen master password
- `passwd` — change your master password (re-encrypts the whole vault with a fresh salt)

### 📝 Entry management
- `add` — add a new entry, typed or auto-generated password
- `get` — retrieve an entry (password masked by default, or shown/copied on request)
- `edit` — update any field of an existing entry
- `remove` — delete an entry (with confirmation)
- `list` — see all entry names, usernames, and last-updated dates — **without** exposing any passwords

### 🎲 Password generation
- Cryptographically secure random password generation (Python's `secrets` module — not `random`)
- Configurable length and symbol inclusion
- Guarantees at least one lowercase, uppercase, digit, and symbol character
- Built-in strength indicator (weak / okay / strong)

### 📋 Clipboard support
- `--copy` flag on `get` and `generate` to copy a password directly to your clipboard instead of printing it
- Auto-detects the right tool per platform:
  - Termux → `termux-clipboard-set`
  - Windows → built-in `clip`
  - macOS → `pbcopy`
  - Linux desktop → `xclip` or `xsel`
  - Fallback → `pyperclip`, if installed

### 🎨 Interface
- Colorized, formatted terminal output via `rich` (panels, tables, styled prompts)
- Hidden password input (no echoing to screen or shell history)
- Clear success/error feedback for every action

### 🌍 Cross-platform
- Pure Python, no OS-specific code paths in the core logic
- Same vault file format works on Termux, Windows, macOS, and Linux — copy the file between devices and unlock it with the same master password anywhere

---

## 4. Installation

### Requirements
- Python 3.9 or newer

### Termux (Android)
```bash
pkg update
pkg install python-cryptography
pip install click rich
```

### Windows / macOS / Linux
```bash
pip install -r requirements.txt
```
`requirements.txt`:
```
cryptography>=41.0
click>=8.1
rich>=13.0
```

> **Note:** on Termux, `cryptography` must be installed via `pkg`, not `pip` — there's no prebuilt wheel for Android on PyPI, so pip tries to compile it from source and fails without Rust. On Windows/macOS/Linux desktop, `pip install` works fine because prebuilt wheels exist for those platforms.

### Optional: clipboard support outside Termux/macOS/Linux-with-xclip
```bash
pip install pyperclip
```

---

## 5. User Guide

### 5.1 First-time setup

```bash
python pmgr.py init
```
You'll be asked to choose and confirm a master password. `pmgr` will tell you if it's weak and let you decide whether to proceed anyway. Choose something you'll actually remember — a 4–5 word passphrase (e.g. `correct horse battery staple 9`) is both strong and memorable.

> ⚠️ There is no "forgot password" option. Write it down somewhere safe if you're worried about forgetting it, separate from the vault itself.

### 5.2 Adding a password

**Type your own password:**
```bash
python pmgr.py add github
```
You'll be prompted for username, password (typed twice to confirm), URL, and notes. The last three are optional — just press Enter to skip.

**Let pmgr generate one for you:**
```bash
python pmgr.py add github --generate
# or shorthand:
python pmgr.py add github -g
```
You can control the generated length:
```bash
python pmgr.py add github -g --length 24
```

### 5.3 Viewing an entry

```bash
python pmgr.py get github
```
By default the password is masked (`••••••••••`). To reveal it:
```bash
python pmgr.py get github --show
```
To copy it straight to your clipboard instead of showing it on screen:
```bash
python pmgr.py get github --copy
```

### 5.4 Listing entries

```bash
python pmgr.py list
```
Shows a table of entry names, usernames, URLs, and last-updated dates. **Passwords are never shown in this view**, even masked — this command is safe to run with someone glancing at your screen.

Filter by name:
```bash
python pmgr.py list --search git
```

### 5.5 Editing an entry

```bash
python pmgr.py edit github
```
Walks you through each field, showing the current value as the default (press Enter to keep it). You'll be asked separately whether you want to change the password, and if so, whether to generate a new one or type your own.

### 5.6 Removing an entry

```bash
python pmgr.py remove github
```
Asks for confirmation before deleting — this cannot be undone.

### 5.7 Changing your master password

```bash
python pmgr.py passwd
```
You'll unlock the vault with your current password, then set a new one. The entire vault is re-encrypted with a **fresh random salt** — not just re-wrapped, genuinely re-encrypted from scratch.

### 5.8 Generating a password without saving it

Useful when a site's own signup form needs a password, and you just want a strong one without creating a vault entry yet:
```bash
python pmgr.py generate
python pmgr.py generate --length 32
python pmgr.py generate --no-symbols
python pmgr.py generate --copy
```

### 5.9 Command reference

| Command | Purpose |
|---|---|
| `init` | Create a new vault |
| `add <name> [-g] [-l N]` | Add an entry, optionally auto-generated |
| `get <name> [--show] [--copy]` | View an entry |
| `list [--search TERM]` | List all entry names (no passwords) |
| `edit <name>` | Update an existing entry |
| `remove <name>` | Delete an entry |
| `passwd` | Change the master password |
| `generate [-l N] [--no-symbols] [--copy]` | Generate a password, no vault needed |

Run `python pmgr.py <command> --help` for full details on any command.

### 5.10 Backing up your vault

Your entire vault is one file:
```
~/.pmgr/vault.dat
```
To back it up, just copy that file — to a USB drive, another device, encrypted cloud storage, wherever you trust. It's already encrypted, so copying it around doesn't expose anything on its own; it's only readable with your master password.

To restore it on a new device: install `pmgr` there, then place your backed-up `vault.dat` at `~/.pmgr/vault.dat` before running any command (skip `init`, since a vault already exists).

### 5.11 Moving between Termux and a PC

Because the vault format is identical everywhere, you can:
1. Copy `~/.pmgr/vault.dat` from your phone to your PC (or vice versa) via USB, cloud sync, `scp`, etc.
2. Place it at `~/.pmgr/vault.dat` on the new device
3. Run `python pmgr.py list` and unlock with the same master password

---

## 6. Threat Model — What This Protects Against (and What It Doesn't)

**Protects against:**
- Someone else reading your vault file (it's encrypted, and unreadable without your master password)
- Someone stealing the vault file and brute-forcing it offline (600,000 PBKDF2 iterations make each guess expensive)
- Silent tampering with the vault file (Fernet's HMAC will cause decryption to fail rather than return corrupted data)
- Other local user accounts on the same machine reading your vault (Unix file permissions)

**Does not protect against:**
- Malware or keyloggers already running on your device while you type your master password
- Someone who already knows your master password
- Physical access to an unlocked terminal session where you've just displayed a password with `--show`
- Loss of the master password itself (no recovery — this is intentional)

This is a personal, single-user tool. It's built for people managing their own credentials responsibly, not as a substitute for enterprise credential management or multi-user access control.

## License

Copyright (c) 2026 Sadi ul Hakim

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
