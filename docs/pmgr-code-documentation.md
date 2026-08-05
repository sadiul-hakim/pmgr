# pmgr — Code Documentation

**A line-by-line walkthrough of `pmgr.py`, written for someone who knows basic Python but hasn't used these specific libraries before.**

This document explains *every* variable, function, and library in the file — what it's for, how it works, and why it's written that way. Read it top to bottom, in the same order as the code.

---

## 1. The Big Picture First

Before diving into code, here's the mental model:

```
Your master password
        │
        ▼
  [turned into an encryption key]   ← PBKDF2 (a "key derivation function")
        │
        ▼
  [used to lock/unlock the vault]   ← Fernet (an encryption tool)
        │
        ▼
  vault.dat on disk (unreadable without the key)
```

The whole file is organized around this idea. Nearly every function either:
- **(a)** helps turn a password into a key, or
- **(b)** helps encrypt/decrypt data with that key, or
- **(c)** is a CLI command that ties (a) and (b) together with something the user asked for (add a password, view one, etc.)

Keep that shape in your head — it'll make the rest of this much easier to follow.

---

## 2. Libraries Used, and What Each One Is For

At the top of the file:

```python
import base64
import json
import os
import secrets
import shutil
import string
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

import click
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich import box
```

| Import | What it's for in this file |
|---|---|
| `base64` | Converts raw encrypted bytes into plain text (and back), so they can be safely stored inside a JSON file. Encrypted data is just a stream of bytes — some of those bytes aren't valid text characters, so `base64` re-encodes them into a safe subset of letters/numbers/symbols. |
| `json` | Reads and writes the vault file, which is stored in JSON format (`{"key": "value"}` style). |
| `os` | Two specific jobs: `os.chmod()` sets file permissions (who can read/write the vault file), and `os.replace()` safely renames a file — used so a crash mid-save can't corrupt your vault. |
| `secrets` | Python's **cryptographically secure** random number generator. Used to create the random "salt" and to generate random passwords. This is different from the `random` module — `random` is predictable enough to be *guessed* by an attacker, `secrets` is not. |
| `shutil` | Just one function used: `shutil.which()`, which checks if a command-line program (like `pbcopy` or `xclip`) exists on the system — used for clipboard support. |
| `string` | Gives ready-made character sets like `string.ascii_letters` (a-z, A-Z) and `string.punctuation` (`!@#$...`) — used to build the password generator's character pool. |
| `subprocess` | Lets Python run other command-line programs and send them data. Used to pipe a password into clipboard tools like `pbcopy` or `clip`. |
| `sys` | Just `sys.exit(1)` — stops the program immediately with an "error" exit code, used whenever something fails badly enough that continuing doesn't make sense (e.g., wrong password). |
| `time` | Imported but not currently used in the code — safe to remove if you want, doesn't affect anything. |
| `datetime` | Records timestamps — e.g., "this entry was last updated at ...". |
| `pathlib.Path` | A modern, cross-platform way to build file paths. `Path.home()` finds your home folder (`/home/you` on Linux, `C:\Users\you` on Windows) without you having to know which OS you're on. |
| `click` | The library that turns this file into a proper CLI tool — it handles reading commands like `pmgr add github`, parsing options like `--generate`, and generating `--help` text automatically. |
| `cryptography` (Fernet, PBKDF2HMAC, hashes) | The actual encryption engine. Explained in depth in Section 4. |
| `rich` (Console, Panel, Prompt, Table, etc.) | Makes the terminal output look nice — colors, boxes, tables, hidden password input. Purely cosmetic/UX, no security role. |

---

## 3. Configuration Constants

```python
VAULT_DIR = Path.home() / ".pmgr"
VAULT_PATH = VAULT_DIR / "vault.dat"
KDF_ITERATIONS = 600_000
SALT_SIZE = 16

console = Console()
```

- **`VAULT_DIR`** — the folder where your vault lives: `~/.pmgr` (a hidden folder in your home directory, following the common Unix convention of dot-prefixed folders for app data).
- **`VAULT_PATH`** — the full path to the actual vault file: `~/.pmgr/vault.dat`.
- **`KDF_ITERATIONS`** — how many times the password-to-key process repeats internally (600,000). Explained fully in Section 4.2 — this number is the main thing standing between a stolen file and a cracked password.
- **`SALT_SIZE`** — the salt (explained below) is 16 bytes long. This is a standard, secure size for this purpose.
- **`console`** — a single shared `rich.Console` object used everywhere in the file to print styled/colored text. Creating it once at the top and reusing it is a common `rich` pattern.

---

## 4. Crypto Helpers — The Heart of the Program

This is the most important section to understand. Everything else in the file is just "plumbing" around these three functions.

### 4.1 What is a "salt"?

You'll see the word `salt` everywhere. A salt is just **a random chunk of bytes**, unique to your vault, generated once when you run `init`. It's not secret — it's stored right there in the vault file in plain sight.

Its job: without a salt, two people with the same password would produce the *exact same* encryption key. An attacker could pre-compute keys for millions of common passwords once, then check them instantly against *any* stolen vault. With a random salt mixed in, that pre-computation is useless — the attacker has to redo the expensive work specifically against *your* salt, every single time.

### 4.2 `derive_key()` — turning a password into a key

```python
def derive_key(master_password: str, salt: bytes, iterations: int = KDF_ITERATIONS) -> bytes:
    """Derive a 32-byte Fernet key from the master password + salt via PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    raw_key = kdf.derive(master_password.encode("utf-8"))
    return base64.urlsafe_b64encode(raw_key)
```

Walking through it:
- **`PBKDF2HMAC(...)`** sets up a "key derivation function" — a deliberately slow, repeatable algorithm for turning a password into a fixed-size encryption key.
  - `algorithm=hashes.SHA256()` — the specific hashing algorithm used internally, on each of the 600,000 rounds.
  - `length=32` — we want a 32-byte (256-bit) output key.
  - `salt=salt` — mixes in the random salt discussed above.
  - `iterations=iterations` — how many times to repeat the process internally (600,000 by default). This is the "slow" part, done on purpose: it makes each password *guess* take a small but real amount of time, so trying millions of guesses becomes impractical.
- **`kdf.derive(master_password.encode("utf-8"))`** — actually runs the algorithm. `.encode("utf-8")` converts the password from a Python string into raw bytes, since the crypto library works with bytes, not text.
- **`base64.urlsafe_b64encode(raw_key)`** — the raw 32 bytes aren't guaranteed to be valid/printable text, so this re-encodes them into a safe base64 string. This specific format is what the `Fernet` encryption class expects as its key.

**Key idea:** if you run this function twice with the *same* password and *same* salt, you always get the *same* key back. That's what makes decryption possible later — you re-derive the same key from the password you type in, rather than storing the key anywhere.

### 4.3 `encrypt_vault()` — locking your data

```python
def encrypt_vault(data: dict, master_password: str, salt: bytes, iterations: int) -> bytes:
    key = derive_key(master_password, salt, iterations)
    f = Fernet(key)
    plaintext = json.dumps(data).encode("utf-8")
    return f.encrypt(plaintext)
```

- `data` here is a Python dictionary — your entire vault's contents (all entries), e.g. `{"entries": {"github": {...}, "email": {...}}}`.
- `derive_key(...)` gets the encryption key, as explained above.
- `Fernet(key)` creates an "encryptor/decryptor" object using that key.
- `json.dumps(data)` converts the dictionary into a JSON text string; `.encode("utf-8")` turns that string into bytes (Fernet needs bytes, not strings).
- `f.encrypt(plaintext)` does the actual encryption, returning a scrambled block of bytes called a **token**. This token includes both the encrypted data *and* a built-in integrity check (more in 4.5).

### 4.4 `decrypt_vault()` — unlocking your data

```python
def decrypt_vault(token: bytes, master_password: str, salt: bytes, iterations: int) -> dict:
    key = derive_key(master_password, salt, iterations)
    f = Fernet(key)
    plaintext = f.decrypt(token)  # raises InvalidToken on wrong password / tampering
    return json.loads(plaintext.decode("utf-8"))
```

The exact reverse of `encrypt_vault()`:
- Re-derive the same key from the password + salt.
- `f.decrypt(token)` attempts to unscramble the token.
- **If the password is wrong**, the derived key is wrong, and `f.decrypt()` throws an `InvalidToken` exception — this is how the program knows to say "Wrong master password."
- If it succeeds, `json.loads(...)` turns the decrypted JSON text back into a Python dictionary.

### 4.5 What is `Fernet`, actually?

`Fernet` (from the `cryptography` library) bundles together two things in one simple package:
1. **AES-128-CBC** — the actual encryption algorithm that scrambles your data so it's unreadable without the key.
2. **HMAC-SHA256** — an integrity check "stapled" onto the encrypted data. When you decrypt, Fernet checks this before returning anything. If even one byte was altered (corruption, tampering, or a wrong key), decryption fails loudly instead of silently returning garbage data.

You don't need to know how AES or HMAC work internally to use this file safely — `Fernet` is specifically designed so you can't misuse it by accident, unlike using raw AES directly.

---

## 5. Vault File I/O — Reading and Writing to Disk

### 5.1 `vault_exists()`

```python
def vault_exists() -> bool:
    return VAULT_PATH.exists()
```
Just checks: does the vault file exist yet? Used to stop commands like `add` or `get` from running before you've run `init`.

### 5.2 `read_vault_file()`

```python
def read_vault_file() -> dict:
    """Read the raw (still-encrypted) vault file into a dict of metadata + token."""
    with open(VAULT_PATH, "r") as fh:
        raw = json.load(fh)
    raw["salt"] = base64.b64decode(raw["salt"])
    raw["token"] = base64.b64decode(raw["token"])
    return raw
```

The vault file on disk looks like this (see `write_vault_file()` below for exactly how it's built):
```json
{
  "version": 1,
  "kdf": "pbkdf2_sha256",
  "iterations": 600000,
  "salt": "base64-text-here",
  "token": "base64-text-here"
}
```
This function:
1. Opens the file and parses the JSON into a Python dict (`raw`).
2. The `salt` and `token` fields were stored as base64 *text* (so they fit safely inside JSON) — this converts them back into raw *bytes*, since that's what the crypto functions actually need.

### 5.3 `write_vault_file()`

```python
def write_vault_file(salt: bytes, iterations: int, token: bytes) -> None:
    VAULT_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": 1,
        "kdf": "pbkdf2_sha256",
        "iterations": iterations,
        "salt": base64.b64encode(salt).decode("ascii"),
        "token": base64.b64encode(token).decode("ascii"),
    }
    tmp_path = VAULT_PATH.with_suffix(".tmp")
    with open(tmp_path, "w") as fh:
        json.dump(payload, fh)
    os.replace(tmp_path, VAULT_PATH)
    try:
        os.chmod(VAULT_PATH, 0o600)
    except OSError:
        pass  # best-effort on platforms that don't support unix perms
```

Step by step:
1. `VAULT_DIR.mkdir(parents=True, exist_ok=True)` — makes sure `~/.pmgr` exists, creating it if needed. `exist_ok=True` means "don't error if it's already there."
2. Builds the `payload` dictionary — the same shape shown above. `base64.b64encode(...)` converts the raw salt/token bytes into base64 text so they're valid inside JSON, and `.decode("ascii")` converts that base64 result from bytes into a plain Python string.
3. **Writes to a temporary file first** (`vault.tmp`), not directly to `vault.dat`. Then `os.replace(tmp_path, VAULT_PATH)` atomically renames it into place. This is a safety technique: if the program crashes or loses power *while writing*, you're left with either the old complete vault file or a harmless leftover `.tmp` file — never a half-written, corrupted `vault.dat`.
4. `os.chmod(VAULT_PATH, 0o600)` sets file permissions so only your user account can read/write the file. `0o600` is Unix permission notation — the `0o` means "this is an octal number," and `600` means "owner: read+write, everyone else: nothing." Wrapped in `try/except` because Windows doesn't support this permission model the same way — it just gets skipped there instead of crashing.

### 5.4 `save_vault()`

```python
def save_vault(data: dict, master_password: str, salt: bytes, iterations: int) -> None:
    token = encrypt_vault(data, master_password, salt, iterations)
    write_vault_file(salt, iterations, token)
```
A convenience wrapper: encrypt the data, then write it to disk. Almost every command that changes your vault ends by calling this one function.

### 5.5 `unlock_vault()`

```python
def unlock_vault(master_password: str) -> tuple[dict, bytes, int]:
    """Returns (decrypted_data, salt, iterations). Exits with error on failure."""
    raw = read_vault_file()
    try:
        data = decrypt_vault(raw["token"], master_password, raw["salt"], raw["iterations"])
    except InvalidToken:
        console.print("\n[bold red]✗ Wrong master password (or vault is corrupted).[/bold red]\n")
        sys.exit(1)
    return data, raw["salt"], raw["iterations"]
```
The main "open the vault" function used by nearly every command:
1. Reads the raw encrypted file from disk.
2. Tries to decrypt it with the password you typed.
3. If that fails (`InvalidToken`), prints an error and exits the whole program with `sys.exit(1)` — `1` is the conventional "something went wrong" exit code.
4. If it succeeds, returns three things as a **tuple**: the decrypted data (dict), the salt (needed again later if you save changes), and the iteration count.

> `tuple[dict, bytes, int]` in the function signature is a *type hint* — it tells readers (and some editors) "this function returns a tuple containing a dict, then bytes, then an int," in that order. It doesn't change how the code runs; it's documentation for humans and tools.

### 5.6 `prompt_master_password()`

```python
def prompt_master_password(confirm_prompt: bool = False) -> str:
    pw = Prompt.ask("[bold cyan]Master password[/bold cyan]", password=True)
    if confirm_prompt:
        pw2 = Prompt.ask("[bold cyan]Confirm master password[/bold cyan]", password=True)
        if pw != pw2:
            console.print("[bold red]✗ Passwords did not match.[/bold red]")
            sys.exit(1)
    return pw
```
Asks the user to type their master password using `rich`'s `Prompt.ask(..., password=True)` — the `password=True` part hides the typed characters, just like a normal password field. If `confirm_prompt=True` (used during `init` and `passwd`), it asks a second time and checks both match, exiting if they don't.

---

## 6. Password Strength & Generation

### 6.1 `password_strength_label()`

```python
def password_strength_label(pw: str) -> tuple[str, str]:
    """Very small heuristic strength check. Returns (label, color)."""
    score = 0
    if len(pw) >= 8:
        score += 1
    if len(pw) >= 14:
        score += 1
    if any(c.islower() for c in pw) and any(c.isupper() for c in pw):
        score += 1
    if any(c.isdigit() for c in pw):
        score += 1
    if any(c in string.punctuation for c in pw):
        score += 1

    if score <= 2:
        return "weak", "red"
    if score <= 4:
        return "okay", "yellow"
    return "strong", "green"
```
A simple point-scoring system — not cryptographic analysis, just a helpful nudge:
- +1 point for being at least 8 characters
- +1 more point for being at least 14 characters (so this can add up to 2 points total for long passwords)
- +1 point for having both lowercase *and* uppercase letters
- +1 point for having at least one digit
- +1 point for having at least one punctuation symbol

`any(c.islower() for c in pw)` is a **generator expression** — it checks each character `c` in the password string `pw`, and `any(...)` returns `True` if *at least one* of them is lowercase. This is a common, readable Python pattern for "does this collection contain something matching a condition?"

Based on the total score (0–5), it returns a tuple of `(label, color)` — e.g. `("weak", "red")` — used elsewhere to print colored feedback like `Strength: weak` in red text.

### 6.2 `generate_password()`

```python
def generate_password(length: int = 20, use_symbols: bool = True) -> str:
    alphabet = string.ascii_letters + string.digits
    if use_symbols:
        alphabet += "!@#$%^&*()-_=+[]{};:,.?"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw)
                and any(c.isdigit() for c in pw)
                and (not use_symbols or any(c in string.punctuation for c in pw))):
            return pw
```
- `alphabet` is built up as a string of every character the generator is allowed to use: letters (`string.ascii_letters` = `abc...XYZ`), digits (`string.digits` = `0123456789`), and optionally symbols.
- The `while True:` loop keeps generating candidate passwords until one satisfies all the rules, then returns it (`return pw` exits the loop and the function at the same time).
- `"".join(secrets.choice(alphabet) for _ in range(length))` — this builds the password one character at a time:
  - `range(length)` just gives us `length` repetitions (we don't care about the loop variable's value, hence naming it `_` by convention — "this value isn't used").
  - `secrets.choice(alphabet)` securely picks one random character from `alphabet`.
  - `"".join(...)` glues all those characters together into a single string.
- The `if (...)` check afterward makes sure the *specific* random password actually contains at least one of each required character type (lowercase, uppercase, digit, and symbol if enabled) — since pure randomness could occasionally produce a password missing a category (e.g. no digits at all) purely by chance, especially on short lengths. If it fails the check, the loop just tries again.

**Why `secrets.choice` and not `random.choice`?** Python's regular `random` module is a *predictable* pseudo-random number generator — good for games or simulations, but an attacker who studies its internal state can sometimes predict future "random" values. `secrets` is built specifically for security-sensitive randomness (passwords, tokens, keys) and doesn't have that weakness.

### 6.3 `copy_to_clipboard()`

```python
def copy_to_clipboard(text: str) -> bool:
    ...
```
Tries several different clipboard tools, one after another, depending on the platform — returns `True` on the first one that works, or `False` if none did.

- `shutil.which("termux-clipboard-set")` checks if that command exists on the system's `PATH` (the list of folders the OS searches when you type a command name). If found, run it via `subprocess.run([...], input=text.encode(), check=True)` — this launches the tool as a separate process and *pipes* the password's bytes into its standard input, exactly as if you'd typed `echo "password" | termux-clipboard-set` in the terminal. `check=True` makes it raise an exception if the tool exits with an error, which the surrounding `try/except` catches quietly.
- `os.name == "nt"` — `"nt"` is Python's internal code for "Windows." This branch uses Windows' built-in `clip` command. Note the `text.encode("utf-16le")` here instead of plain `.encode()` — Windows' `clip` command specifically expects UTF-16 Little Endian encoded text, unlike the other tools which are fine with standard UTF-8.
- `pbcopy` — macOS's built-in clipboard tool.
- `xclip` / `xsel` — the two most common clipboard tools on Linux desktops (not built-in — the user needs one of them installed).
- **Fallback**: if none of the above are available, tries the optional third-party `pyperclip` package, if it happens to be installed.
- Every branch is wrapped in `try/except Exception: pass` — if any tool fails to run for any reason, we silently move to the next option rather than crashing the whole program over a clipboard failure.

---

## 7. UI Helpers

### 7.1 `banner()`

```python
def banner():
    console.print(
        Panel(
            Align.center("[bold white]pmgr[/bold white] [dim]— secure local password vault[/dim]"),
            box=box.ROUNDED,
            style="cyan",
        )
    )
```
Prints the boxed "pmgr" title banner you see when you run `pmgr init`. `Panel(...)` draws a bordered box around content; `Align.center(...)` centers the text inside it; `box=box.ROUNDED` picks a border style with rounded corners (one of several styles `rich` offers). The text itself uses `rich`'s inline markup — `[bold white]...[/bold white]` and `[dim]...[/dim]` are style tags, similar in spirit to simple HTML tags, that `rich` interprets and renders as actual terminal colors/styles.

### 7.2 `mask()`

```python
def mask(pw: str) -> str:
    return "•" * min(len(pw), 16)
```
Used by the `get` command to hide a password by default. `"•" * N` repeats the bullet character `N` times. `min(len(pw), 16)` caps the number of dots at 16 even for very long passwords, so the masked output doesn't visually reveal the password's exact length for long entries.

---

## 8. The CLI Itself — How `click` Wires Everything Together

### 8.1 The command group

```python
@click.group(context_settings={"help_option_names": ["-h", "--help"]})
def cli():
    """pmgr — a secure, file-based, single-user CLI password manager."""
    pass
```
`@click.group()` is a **decorator** — a function that wraps another function to add behavior. Here, it turns the plain function `cli()` into the root of a command-line tool that can have *subcommands* (like `add`, `get`, `list`, etc.) attached to it. `context_settings={"help_option_names": ["-h", "--help"]}` just means both `-h` and `--help` will show help text, not just `--help` alone. The `"""docstring"""` inside becomes the text shown when you run `pmgr --help`.

### 8.2 How each command is defined

Every command follows the same pattern. Take `add` as an example:

```python
@cli.command()
@click.argument("name")
@click.option("--generate", "-g", is_flag=True, help="Auto-generate a strong password instead of typing one.")
@click.option("--length", "-l", default=20, show_default=True, help="Length of generated password.")
def add(name, generate, length):
    """Add a new entry to the vault."""
    ...
```
- `@cli.command()` registers this function as a subcommand of the `cli` group — this is what makes `pmgr add ...` work.
- `@click.argument("name")` declares a **required, positional** input — whatever you type right after `add` (e.g. `pmgr add github` → `name = "github"`).
- `@click.option("--generate", "-g", is_flag=True, ...)` declares an optional **flag** — `is_flag=True` means it doesn't take a value, it's just present or absent (`--generate` or `-g` sets `generate = True`; leaving it off means `generate = False`).
- `@click.option("--length", "-l", default=20, ...)` declares an option that *does* take a value, defaulting to `20` if not provided (e.g. `pmgr add github -g --length 24` → `length = 24`).
- Click automatically matches these decorators to the function's parameters by name (`name`, `generate`, `length`) and calls `add(name, generate, length)` for you when the command runs — you never call this function directly.

The other commands (`init`, `get`, `list`, `edit`, `remove`, `passwd`, `generate`) all follow this exact same pattern, just with different arguments/options relevant to what they do.

### 8.3 The vault's in-memory shape

Throughout the commands, you'll see code like:
```python
data["entries"][name] = {
    "username": username,
    "password": secret,
    "url": url,
    "notes": notes,
    "updated": datetime.now().isoformat(),
}
```
Once decrypted, the whole vault is just a nested Python dictionary shaped like this:
```python
{
  "entries": {
    "github": {
      "username": "myuser",
      "password": "S3cret!",
      "url": "github.com",
      "notes": "personal account",
      "updated": "2026-08-02T10:15:00"
    },
    "email": { ... }
  },
  "created": "2026-08-01T09:00:00"
}
```
Every command follows the same three-step recipe:
1. **Unlock** — `unlock_vault(pw_master)` to get the `data` dict.
2. **Modify** the `data` dict in memory using normal Python dictionary operations (`data["entries"][name] = {...}`, `del data["entries"][name]`, etc.) — this doesn't touch the file yet.
3. **Save** — `save_vault(data, pw_master, salt, iterations)` re-encrypts the whole modified dict and writes it back to disk.

`datetime.now().isoformat()` produces a timestamp string like `"2026-08-02T10:15:00.123456"` — a standard, sortable text format for "right now."

### 8.4 Walking through each command briefly

| Command | What it does, step by step |
|---|---|
| **`init`** | Shows the banner, warns if a vault already exists (asks to confirm overwrite), loops asking for a master password until it's confirmed twice and (optionally) accepted despite being weak, generates a random salt with `secrets.token_bytes(SALT_SIZE)`, creates an empty vault (`{"entries": {}, ...}`), and saves it. |
| **`add`** | Requires the vault to exist (`_require_vault()`), unlocks it, checks the entry name isn't already taken, asks for username/password (typed-and-confirmed, or auto-generated)/URL/notes, stores it in `data["entries"][name]`, saves. |
| **`get`** | Unlocks the vault, looks up the entry with `data["entries"].get(name)` (returns `None` if missing, instead of crashing like `data["entries"][name]` would), builds a `rich` table to display it (masking the password unless `--show`), optionally copies the password to the clipboard if `--copy` was passed. |
| **`list`** | Unlocks the vault, optionally filters entries by a search substring (case-insensitive, via `.lower()` on both sides), builds a `rich` table of names/usernames/URLs/dates — deliberately **never includes the password column**. |
| **`edit`** | Unlocks the vault, looks up the entry, walks through each field letting the user press Enter to keep the current value (`Prompt.ask(..., default=entry.get("username", ""))` — if you just hit Enter, `default` is used), separately asks whether to change the password at all, saves the updated entry. |
| **`remove`** | Unlocks the vault, confirms the entry exists, asks for confirmation (`Confirm.ask(...)` returns `True`/`False`), deletes it from the dict with `del data["entries"][name]`, saves. |
| **`passwd`** | Unlocks the vault with the *current* password, asks for and confirms a *new* one (with the same weak-password check as `init`), generates a **brand new random salt**, and saves — meaning the vault is genuinely re-encrypted from scratch, not just "re-labeled." |
| **`generate`** | Doesn't touch the vault at all — just calls `generate_password()` and either prints or copies the result. Useful for generating a password for a site before you've even decided to save it. |

### 8.5 `_require_vault()`

```python
def _require_vault():
    if not vault_exists():
        console.print(f"[red]No vault found at {VAULT_PATH}.[/red] Run [bold]pmgr init[/bold] first.")
        sys.exit(1)
```
A small guard function called at the start of most commands. The leading underscore (`_require_vault`) is a Python convention meaning "this is an internal helper, not meant to be part of the public API of this file" — it's not a CLI command itself (`@cli.command()` isn't used on it), just a plain function other commands call directly.

### 8.6 The entry point

```python
if __name__ == "__main__":
    cli()
```
This is a standard Python idiom. `__name__` is a special built-in variable that equals `"__main__"` only when the file is run directly (e.g. `python pmgr.py add github`), and something else if the file is instead *imported* by another Python file. This guard means: "only start the CLI if this file was run directly — don't auto-run anything if someone imports `pmgr.py` from elsewhere."

---

## 9. Reading the File Top-to-Bottom, One More Time

If you want to trace through a real example — say, running `pmgr get github --show` — here's the call chain:

```
cli() (click group, invisible entry point)
  └─ get(name="github", show=True, copy=False)
       ├─ _require_vault()                     — check vault.dat exists
       ├─ prompt_master_password()             — ask you to type your password
       ├─ unlock_vault(pw_master)
       │    ├─ read_vault_file()               — load salt/token from disk
       │    └─ decrypt_vault(token, pw, salt, iterations)
       │         ├─ derive_key(pw, salt, iterations)   — PBKDF2 → key
       │         └─ Fernet(key).decrypt(token)          — AES+HMAC → plaintext
       ├─ data["entries"].get("github")        — look up the entry in the dict
       └─ Table(...) / console.print(...)      — display it nicely
```

Every other command follows a similar shape — the differences are mostly in what happens *between* unlocking and (optionally) saving.

---

## 10. Glossary — Terms Used Throughout

| Term | Plain-English meaning |
|---|---|
| **Salt** | A random value mixed into password-based encryption so identical passwords don't produce identical keys. Not secret, but must be random and unique. |
| **KDF (Key Derivation Function)** | An algorithm that turns a password into a fixed-size encryption key, deliberately slowed down to resist brute-force guessing. PBKDF2 is one such algorithm. |
| **Iterations** | How many times a KDF repeats its internal process. More iterations = slower to compute = harder to brute-force, at the cost of taking longer each time you unlock the vault. |
| **Token (in Fernet)** | The output of encryption — a self-contained blob that includes the encrypted data plus an integrity check, ready to be decrypted later with the right key. |
| **HMAC** | A technique for detecting tampering — computes a small "fingerprint" tied to both the data and a secret key, so any change to the data (or key) produces a different fingerprint. |
| **Decorator (`@something`)** | Python syntax for wrapping a function with extra behavior without changing its own code. Used heavily by `click` to turn plain functions into CLI commands. |
| **Type hint (`-> bytes`, `: str`)** | Optional annotations describing what type of data a function expects/returns. Ignored at runtime — purely for human readers and code editors. |
| **Context manager (`with open(...) as fh:`)** | A Python pattern that guarantees cleanup (like closing a file) happens automatically, even if an error occurs inside the `with` block. |
