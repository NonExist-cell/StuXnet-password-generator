# Offline Password Manager – GUI Edition

A fully offline, secure, and stylish password manager with a hackerish dark GUI. Built with Python, AES‑256‑GCM encryption, and scrypt KDF.  

---

## Features

- **Fully Offline:** All data is stored locally; no internet required.
- **Strong Encryption:** AES‑256‑GCM + scrypt KDF ensures your vault is secure.
- **GUI:** Dark theme with terminal-green accents using DejaVu Sans Mono.
- **Password Generation:** Strong, customizable passwords with optional avoidance of ambiguous characters.
- **Vault Management:** Add, edit, delete entries, search, copy to clipboard.
- **Automatic Clipboard Clear:** Clears copied passwords after 25 seconds.
- **Single Encrypted Vault File:** Master password never stored; losing it means losing access to your vault.
- **Cross-Platform:** Works on Linux, Windows, macOS (Python 3.9+ recommended).

---

**Why NeonVault?**

Most online password managers store your sensitive credentials on cloud servers. While convenient, this exposes you to potential hacks, data breaches, and unauthorized access. NeonVault is a fully offline password manager, meaning all your passwords are encrypted and stored locally on your device. No cloud, no servers, no accidental leaks. You are in full control, and your master password is never transmitted or stored anywhere.

Using NeonVault minimizes risk while giving you strong cryptography (AES-256-GCM + scrypt KDF), a interface, and automatic strong password generation for every account.

## Installation

1. Clone or download this repository.
2. Install dependencies:


pip install cryptography
