#!/usr/bin/env python3
"""
pmgr - a secure, file-based, single-user CLI password manager.

Security design:
  - Vault contents are encrypted with Fernet (AES-128-CBC + HMAC-SHA256).
  - The encryption key is derived from your master password using
    PBKDF2-HMAC-SHA256 with 600,000 iterations (OWASP 2023 recommendation)
    and a random 16-byte salt, unique per vault.
  - The master password is NEVER stored anywhere, not even hashed.
    It only ever exists in memory for the duration of a command.
  - The vault file on disk is a single encrypted blob (plus salt/iteration
    metadata needed to re-derive the key). Without the correct master
    password, the file is unreadable, even to you.
  - Vault file permissions are locked to 600 (owner read/write only).

This tool is designed to work great in Termux (Android/Linux terminal),
but runs on any system with Python 3.9+.
"""

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

# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------

VAULT_DIR = Path.home() / ".pmgr"
VAULT_PATH = VAULT_DIR / "vault.dat"
KDF_ITERATIONS = 600_000
SALT_SIZE = 16

console = Console()


# --------------------------------------------------------------------------
# Crypto helpers
# --------------------------------------------------------------------------

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


def encrypt_vault(data: dict, master_password: str, salt: bytes, iterations: int) -> bytes:
    key = derive_key(master_password, salt, iterations)
    f = Fernet(key)
    plaintext = json.dumps(data).encode("utf-8")
    return f.encrypt(plaintext)


def decrypt_vault(token: bytes, master_password: str, salt: bytes, iterations: int) -> dict:
    key = derive_key(master_password, salt, iterations)
    f = Fernet(key)
    plaintext = f.decrypt(token)  # raises InvalidToken on wrong password / tampering
    return json.loads(plaintext.decode("utf-8"))


# --------------------------------------------------------------------------
# Vault file I/O
# --------------------------------------------------------------------------

def vault_exists() -> bool:
    return VAULT_PATH.exists()


def read_vault_file() -> dict:
    """Read the raw (still-encrypted) vault file into a dict of metadata + token."""
    with open(VAULT_PATH, "r") as fh:
        raw = json.load(fh)
    raw["salt"] = base64.b64decode(raw["salt"])
    raw["token"] = base64.b64decode(raw["token"])
    return raw


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


def save_vault(data: dict, master_password: str, salt: bytes, iterations: int) -> None:
    token = encrypt_vault(data, master_password, salt, iterations)
    write_vault_file(salt, iterations, token)


def unlock_vault(master_password: str) -> tuple[dict, bytes, int]:
    """Returns (decrypted_data, salt, iterations). Exits with error on failure."""
    raw = read_vault_file()
    try:
        data = decrypt_vault(raw["token"], master_password, raw["salt"], raw["iterations"])
    except InvalidToken:
        console.print("\n[bold red]✗ Wrong master password (or vault is corrupted).[/bold red]\n")
        sys.exit(1)
    return data, raw["salt"], raw["iterations"]


def prompt_master_password(confirm_prompt: bool = False) -> str:
    pw = Prompt.ask("[bold cyan]Master password[/bold cyan]", password=True)
    if confirm_prompt:
        pw2 = Prompt.ask("[bold cyan]Confirm master password[/bold cyan]", password=True)
        if pw != pw2:
            console.print("[bold red]✗ Passwords did not match.[/bold red]")
            sys.exit(1)
    return pw


# --------------------------------------------------------------------------
# Password strength / generation
# --------------------------------------------------------------------------

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


def generate_password(length: int = 20, use_symbols: bool = True) -> str:
    alphabet = string.ascii_letters + string.digits
    if use_symbols:
        alphabet += "!@#$%^&*()-_=+[]{};:,.?"
    # secrets.choice is a CSPRNG-backed generator, suitable for credentials
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        # ensure at least one of each character class, for practical strength
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw)
                and any(c.isdigit() for c in pw)
                and (not use_symbols or any(c in string.punctuation for c in pw))):
            return pw


def copy_to_clipboard(text: str) -> bool:
    """
    Best-effort clipboard copy across platforms:
      - Termux (Android): termux-clipboard-set
      - Windows: builtin 'clip' command
      - macOS: builtin 'pbcopy' command
      - Linux (desktop): xclip or xsel, if installed
      - Fallback: pyperclip, if installed
    """
    # Termux
    if shutil.which("termux-clipboard-set"):
        try:
            subprocess.run(["termux-clipboard-set"], input=text.encode(), check=True)
            return True
        except Exception:
            pass

    # Windows
    if os.name == "nt":
        try:
            subprocess.run(["clip"], input=text.encode("utf-16le"), check=True)
            return True
        except Exception:
            pass

    # macOS
    if shutil.which("pbcopy"):
        try:
            subprocess.run(["pbcopy"], input=text.encode(), check=True)
            return True
        except Exception:
            pass

    # Linux desktop (X11)
    for tool, args in (("xclip", ["xclip", "-selection", "clipboard"]),
                        ("xsel", ["xsel", "--clipboard", "--input"])):
        if shutil.which(tool):
            try:
                subprocess.run(args, input=text.encode(), check=True)
                return True
            except Exception:
                pass

    # Generic fallback
    try:
        import pyperclip  # optional dependency
        pyperclip.copy(text)
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------
# UI helpers
# --------------------------------------------------------------------------

def banner():
    console.print(
        Panel(
            Align.center("[bold white]pmgr[/bold white] [dim]— secure local password vault[/dim]"),
            box=box.ROUNDED,
            style="cyan",
        )
    )


def mask(pw: str) -> str:
    return "•" * min(len(pw), 16)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

@click.group(context_settings={"help_option_names": ["-h", "--help"]})
def cli():
    """pmgr — a secure, file-based, single-user CLI password manager."""
    pass


@cli.command()
def init():
    """Create a new encrypted vault protected by a master password."""
    banner()
    if vault_exists():
        console.print(f"[yellow]A vault already exists at {VAULT_PATH}[/yellow]")
        if not Confirm.ask("Overwrite it and start fresh? [bold red]This deletes all saved entries[/bold red]"):
            console.print("Aborted.")
            return

    console.print("Choose a strong master password. [dim]This is the ONLY thing protecting your vault.[/dim]")
    console.print("[dim]It is never stored — if you forget it, your data cannot be recovered.[/dim]\n")

    while True:
        pw = prompt_master_password(confirm_prompt=True)
        label, color = password_strength_label(pw)
        console.print(f"Strength: [{color}]{label}[/{color}]")
        if label == "weak" and not Confirm.ask("This password is weak. Use it anyway?"):
            continue
        break

    salt = secrets.token_bytes(SALT_SIZE)
    data = {"entries": {}, "created": datetime.now().isoformat()}
    save_vault(data, pw, salt, KDF_ITERATIONS)
    console.print(f"\n[bold green]✓ Vault created at {VAULT_PATH}[/bold green]")
    console.print("[dim]Run 'pmgr add <name>' to store your first password.[/dim]")


@cli.command()
@click.argument("name")
@click.option("--generate", "-g", is_flag=True, help="Auto-generate a strong password instead of typing one.")
@click.option("--length", "-l", default=20, show_default=True, help="Length of generated password.")
def add(name, generate, length):
    """Add a new entry to the vault."""
    _require_vault()
    pw_master = prompt_master_password()
    data, salt, iterations = unlock_vault(pw_master)

    if name in data["entries"]:
        console.print(f"[yellow]An entry named '{name}' already exists. Use 'pmgr edit {name}' instead.[/yellow]")
        return

    username = Prompt.ask("Username / email", default="")
    if generate:
        secret = generate_password(length=length)
        console.print(f"[dim]Generated password:[/dim] [bold]{secret}[/bold]")
    else:
        secret = Prompt.ask("Password", password=True)
        confirm = Prompt.ask("Confirm password", password=True)
        if secret != confirm:
            console.print("[bold red]✗ Passwords did not match. Aborted.[/bold red]")
            return

    url = Prompt.ask("URL (optional)", default="")
    notes = Prompt.ask("Notes (optional)", default="")

    data["entries"][name] = {
        "username": username,
        "password": secret,
        "url": url,
        "notes": notes,
        "updated": datetime.now().isoformat(),
    }
    save_vault(data, pw_master, salt, iterations)
    console.print(f"[bold green]✓ Saved entry '{name}'[/bold green]")


@cli.command()
@click.argument("name")
@click.option("--show/--hide", default=False, help="Show password in plaintext (default: masked).")
@click.option("--copy", "-c", is_flag=True, help="Copy password to clipboard instead of printing it.")
def get(name, show, copy):
    """Retrieve a single entry from the vault."""
    _require_vault()
    pw_master = prompt_master_password()
    data, salt, iterations = unlock_vault(pw_master)

    entry = data["entries"].get(name)
    if not entry:
        console.print(f"[red]No entry named '{name}'.[/red]")
        return

    pw_display = entry["password"] if show else mask(entry["password"])

    table = Table(box=box.SIMPLE_HEAVY, show_header=False)
    table.add_row("[bold]Name[/bold]", name)
    table.add_row("[bold]Username[/bold]", entry.get("username") or "[dim]—[/dim]")
    table.add_row("[bold]Password[/bold]", pw_display)
    table.add_row("[bold]URL[/bold]", entry.get("url") or "[dim]—[/dim]")
    table.add_row("[bold]Notes[/bold]", entry.get("notes") or "[dim]—[/dim]")
    table.add_row("[bold]Updated[/bold]", entry.get("updated", "")[:19].replace("T", " "))
    console.print(table)

    if copy:
        if copy_to_clipboard(entry["password"]):
            console.print("[green]✓ Password copied to clipboard.[/green]")
        else:
            console.print("[yellow]Could not access clipboard on this system.[/yellow]")


@cli.command(name="list")
@click.option("--search", "-s", default=None, help="Filter entries by name substring.")
def list_entries(search):
    """List all entries (names only — passwords are never shown here)."""
    _require_vault()
    pw_master = prompt_master_password()
    data, salt, iterations = unlock_vault(pw_master)

    entries = data["entries"]
    if search:
        entries = {k: v for k, v in entries.items() if search.lower() in k.lower()}

    if not entries:
        console.print("[dim]No entries found.[/dim]")
        return

    table = Table(box=box.ROUNDED, title=f"Vault — {len(entries)} entr{'y' if len(entries)==1 else 'ies'}")
    table.add_column("Name", style="bold cyan")
    table.add_column("Username")
    table.add_column("URL")
    table.add_column("Updated", style="dim")

    for k in sorted(entries):
        e = entries[k]
        table.add_row(k, e.get("username") or "—", e.get("url") or "—", e.get("updated", "")[:10])

    console.print(table)


@cli.command()
@click.argument("name")
def edit(name):
    """Edit an existing entry (leave a field blank to keep its current value)."""
    _require_vault()
    pw_master = prompt_master_password()
    data, salt, iterations = unlock_vault(pw_master)

    entry = data["entries"].get(name)
    if not entry:
        console.print(f"[red]No entry named '{name}'.[/red]")
        return

    console.print("[dim]Press Enter to keep the current value.[/dim]")
    username = Prompt.ask("Username / email", default=entry.get("username", ""))
    change_pw = Confirm.ask("Change password?", default=False)
    if change_pw:
        if Confirm.ask("Auto-generate new password?", default=True):
            secret = generate_password()
            console.print(f"[dim]Generated password:[/dim] [bold]{secret}[/bold]")
        else:
            secret = Prompt.ask("New password", password=True)
    else:
        secret = entry["password"]
    url = Prompt.ask("URL", default=entry.get("url", ""))
    notes = Prompt.ask("Notes", default=entry.get("notes", ""))

    data["entries"][name] = {
        "username": username,
        "password": secret,
        "url": url,
        "notes": notes,
        "updated": datetime.now().isoformat(),
    }
    save_vault(data, pw_master, salt, iterations)
    console.print(f"[bold green]✓ Updated entry '{name}'[/bold green]")


@cli.command()
@click.argument("name")
def remove(name):
    """Delete an entry from the vault."""
    _require_vault()
    pw_master = prompt_master_password()
    data, salt, iterations = unlock_vault(pw_master)

    if name not in data["entries"]:
        console.print(f"[red]No entry named '{name}'.[/red]")
        return

    if not Confirm.ask(f"Delete '{name}'? This cannot be undone"):
        console.print("Aborted.")
        return

    del data["entries"][name]
    save_vault(data, pw_master, salt, iterations)
    console.print(f"[bold green]✓ Deleted '{name}'[/bold green]")


@cli.command()
def passwd():
    """Change the master password (re-encrypts the entire vault)."""
    _require_vault()
    console.print("Enter your [bold]current[/bold] master password to unlock the vault.")
    old_pw = prompt_master_password()
    data, salt, iterations = unlock_vault(old_pw)

    console.print("\nNow choose a [bold]new[/bold] master password.")
    while True:
        new_pw = prompt_master_password(confirm_prompt=True)
        label, color = password_strength_label(new_pw)
        console.print(f"Strength: [{color}]{label}[/{color}]")
        if label == "weak" and not Confirm.ask("This password is weak. Use it anyway?"):
            continue
        break

    new_salt = secrets.token_bytes(SALT_SIZE)  # fresh salt on password change
    save_vault(data, new_pw, new_salt, KDF_ITERATIONS)
    console.print("[bold green]✓ Master password changed.[/bold green]")


@cli.command()
@click.option("--length", "-l", default=20, show_default=True, help="Password length.")
@click.option("--no-symbols", is_flag=True, help="Exclude punctuation symbols.")
@click.option("--copy", "-c", is_flag=True, help="Copy result to clipboard instead of printing it.")
def generate(length, no_symbols, copy):
    """Generate a strong random password (does not touch the vault)."""
    pw = generate_password(length=length, use_symbols=not no_symbols)
    label, color = password_strength_label(pw)
    if copy:
        if copy_to_clipboard(pw):
            console.print(f"[green]✓ Copied to clipboard[/green]  [dim]({label})[/dim]")
        else:
            console.print("[yellow]Clipboard unavailable — printing instead:[/yellow]")
            console.print(f"[bold]{pw}[/bold]")
    else:
        console.print(f"[bold]{pw}[/bold]  [dim]({label})[/dim]")


def _require_vault():
    if not vault_exists():
        console.print(f"[red]No vault found at {VAULT_PATH}.[/red] Run [bold]pmgr init[/bold] first.")
        sys.exit(1)


if __name__ == "__main__":
    cli()
