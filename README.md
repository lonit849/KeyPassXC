# 🔐 KeyPassXC - Secure Password Manager in C

A KeePassXC-style password manager built from scratch in C. AES-256 encryption, auto-lock, categories, password generator with strength meter, and 4-layer backup system.

![C](https://img.shields.io/badge/C-100%25-blue)
![AES-256](https://img.shields.io/badge/Encryption-AES--256-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

## ✨ Features

| Feature | Description |
|---|---|
| **AES-256 + PBKDF2** | Military-grade encryption, 100,000 iterations |
| **HMAC Tamper Detection** | Editing 1 byte in vault is detected, auto-restores from backup |
| **Auto-Lock (60s)** | Background thread locks vault after idle, wipes key from RAM |
| **Categories** | Organize by Social / Bank / School / Custom |
| **Generator** | `gen 16` / `gen 32` / `gen 64` - custom length |
| **Strength Meter** | Bits calculation + WEAK → VERY STRONG rating |
| **Clipboard** | Auto-copy generated passwords (xclip / wl-copy / Termux) |
| **Hidden Password** | Master password shows `****` |
| **4 Backups** | `vault.dat.bak` + `~/.keypass_backup/` + `Android/data/` + Cloud |
| **GUI** | Colored table UI, clear screen, boxed menus |

## 🚀 Quick Start

### Termux (Android)
```bash
pkg install openssl clang termux-api
git clone https://github.com/YOUR-USERNAME/KeyPassXC.git
cd KeyPassXC
make
./keypass
