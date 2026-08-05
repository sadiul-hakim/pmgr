# Installing pmgr as a Command-Line Tool

This turns `pmgr.py` from a script you run with `python pmgr.py ...` into a real command: `pmgr`, callable from anywhere.

Works on: **Termux (Android)**, **Ubuntu/Debian**, **Fedora/RHEL**, **Arch**, and any other standard Linux distribution. The core method is identical everywhere — only the very first step (installing `cryptography`) differs slightly, explained below.

---

## Why Termux Needs One Extra Step

Regular Linux distributions (Ubuntu, Fedora, Arch, etc.) use a system library called **glibc**. Android — and therefore Termux — uses a different one called **Bionic libc**.

The `cryptography` Python package ships **prebuilt binaries** on PyPI for glibc-based Linux, so on a normal Linux machine, `pip install cryptography` just downloads a ready-made binary and finishes instantly.

Termux doesn't match any of those prebuilt binaries, so `pip` falls back to **compiling `cryptography` from source** — which requires the Rust toolchain and fails on a fresh Termux install without it.

**The fix:** install `cryptography` via Termux's own package manager (`pkg`), which maintains a version precompiled specifically for Android, instead of letting `pip` try to build it.

This is the *only* difference between the two paths below.

---

## Path A — Termux (Android)

### 1. Install dependencies

```bash
pkg update
pkg install python python-cryptography
pip install click rich
```

### 2. Get the project files onto your device

If you haven't already:
```bash
termux-setup-storage
```
Then copy the files (downloaded via browser, or however you received them) into a project folder:
```bash
mkdir -p ~/pmgr-tool
cp ~/storage/downloads/pmgr.py ~/pmgr-tool/
cp ~/storage/downloads/pyproject.toml ~/pmgr-tool/
```

### 3. Install it as a command

```bash
cd ~/pmgr-tool
pip install --no-deps -e .
```

`--no-deps` is important here: without it, `pip` would try to reinstall `cryptography` itself (from source) to satisfy `pyproject.toml`, undoing what you just fixed in Step 1. Since `cryptography`, `click`, and `rich` are already installed, this flag tells `pip` to skip dependency resolution and just register the `pmgr` command.

### 4. Verify

```bash
pmgr --help
```

---

## Path B — Standard Linux (Ubuntu, Debian, Fedora, Arch, etc.)

### 1. Install dependencies

No special handling needed — `pip` can install everything directly, including `cryptography`, since prebuilt wheels exist for glibc-based Linux:

```bash
sudo apt install python3-pip python3-venv   # Debian/Ubuntu
# or: sudo dnf install python3-pip           # Fedora
# or: sudo pacman -S python-pip              # Arch
```

*(You likely already have Python and pip if you're on a desktop/server Linux distro — this step just ensures `pip` itself is present.)*

### 2. Get the project files

```bash
mkdir -p ~/pmgr-tool
cp /path/to/pmgr.py ~/pmgr-tool/
cp /path/to/pyproject.toml ~/pmgr-tool/
```

### 3. Install it as a command

```bash
cd ~/pmgr-tool
pip install -e .
```

No `--no-deps` needed — `pip` resolves and installs `cryptography`, `click`, and `rich` automatically, all as prebuilt binaries.

> **Externally-managed-environment error?** Some newer Debian/Ubuntu versions block system-wide `pip install` by default (PEP 668). If you hit that, either add `--break-system-packages` to the command above, or better, use a virtual environment:
> ```bash
> python3 -m venv ~/.venvs/pmgr
> source ~/.venvs/pmgr/bin/activate
> pip install -e ~/pmgr-tool
> ```
> With a venv, you'll need to `source ~/.venvs/pmgr/bin/activate` in each new terminal session before `pmgr` is available — or add that line to your `~/.bashrc` to make it automatic.

### 4. Verify

```bash
pmgr --help
```

---

## Using It

Once installed (either path), it behaves identically everywhere:

```bash
pmgr init                    # create a new vault
pmgr add github               # add an entry
pmgr get github --show        # view a password
pmgr list                     # list all entries
```

It works from **any directory** — you don't need to `cd` into the project folder anymore.

---

## The `-e` Flag — What It Means

`pip install -e .` is an **editable install**. It means: "link the `pmgr` command directly to this source file, rather than copying it somewhere else." If you edit `pmgr.py` later, the changes take effect immediately — no reinstalling required. This is convenient while you're still actively tweaking the code. If you'd rather install a frozen, unlinked copy instead, drop the `-e`:
```bash
pip install .
```

---

## Uninstalling

Same command on every platform:
```bash
pip uninstall pmgr-cli
```
(Your vault file at `~/.pmgr/vault.dat` is untouched by this — uninstalling the command doesn't delete your data.)

---

## Troubleshooting

**`pmgr: command not found` after installing**
Check that pip's script directory is on your `PATH`:
```bash
echo $PATH
```
Termux usually includes `/data/data/com.termux/files/usr/bin` automatically. On desktop Linux with a venv, make sure the venv is activated (`source .../bin/activate`) in the terminal session you're using.

**Build errors mentioning Rust/maturin (Termux only)**
This means `cryptography` is being installed via `pip` instead of `pkg`. Run:
```bash
pip uninstall cryptography
pkg install python-cryptography
```
then retry `pip install --no-deps -e .`

**"externally-managed-environment" error (Debian/Ubuntu, desktop Linux only)**
See the note in Step 1 of Path B above — use `--break-system-packages` or a virtual environment.
