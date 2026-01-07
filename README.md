# RustPW - Secure Password Manager

A secure, cross-platform desktop password manager built with Rust and the Iced GUI framework. RustPW provides strong encryption for your passwords with a clean, dark-themed interface.

![RustPW Screenshot](assets/icon.png)

## Features

- **Strong Encryption**: AES-256 encryption with multiple cipher modes (GCM, CBC, CTR)
- **Secure Key Derivation**: PBKDF2 with configurable iterations (default: 100,000)
- **Category Organization**: Organize passwords into custom categories
- **Password Generator**: Built-in generator with strength calculation
- **Auto-Lock**: Automatic vault locking after configurable inactivity period
- **Clipboard Security**: Automatic clipboard clearing after copying passwords
- **Cross-Platform**: Runs on Windows, Linux, and macOS
- **Dark Theme**: Easy on the eyes with a modern dark interface
- **Memory Safety**: Sensitive data is zeroized from memory when locked

## Table of Contents

- [Architecture](#architecture)
- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Building on Linux](#building-on-linux)
  - [Building on Windows](#building-on-windows)
  - [Building on macOS](#building-on-macos)
- [Usage](#usage)
  - [Creating a Vault](#creating-a-vault)
  - [Managing Entries](#managing-entries)
  - [Managing Categories](#managing-categories)
  - [Password Generator](#password-generator)
- [Configuration](#configuration)
  - [Important Note on Cipher Mode](#important-note-on-cipher-mode)
- [Vault File Format](#vault-file-format)
- [Security Model](#security-model)
  - [Corruption Prevention](#corruption-prevention)
- [License](#license)

## Architecture

RustPW is a single-binary application with all code contained in `src/main.rs` (~3000 lines). The architecture follows Iced's Elm-inspired pattern.

### Core Components

```
┌─────────────────────────────────────────────────────────────┐
│                        RustPW Application                   │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   Config    │  │ VaultCrypto │  │     VaultData       │  │
│  │  (JSON)     │  │ (AES-256)   │  │  (Categories/       │  │
│  │             │  │             │  │   Entries)          │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────┐    │
│  │                    GUI Layer (Iced)                 │    │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────┐  │    │
│  │  │ Startup  │ │   Main   │ │ Dialogs  │ │ Locked │  │    │
│  │  │  Screen  │ │  Screen  │ │          │ │ Screen │  │    │
│  │  └──────────┘ └──────────┘ └──────────┘ └────────┘  │    │
│  └─────────────────────────────────────────────────────┘    │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────┐    │
│  │              Message-Based State Management         │    │
│  │         (update function handles all events)        │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

### Module Overview

| Component | Description |
|-----------|-------------|
| **Config** | JSON configuration stored in `rustpw.conf` alongside the executable |
| **VaultCrypto** | Handles all encryption/decryption with AES-256 and PBKDF2 |
| **VaultData** | In-memory vault structure with categories HashMap and metadata |
| **PasswordGenerator** | Password generation with entropy-based strength calculation |
| **RustPw** | Main application state implementing Iced's Application trait |
| **Message** | Enum containing all UI events and actions |
| **Screen** | Enum representing different application screens |

### Dependencies

| Crate | Purpose |
|-------|---------|
| `iced` | Cross-platform GUI framework |
| `aes-gcm`, `aes`, `cbc`, `ctr` | AES encryption implementations |
| `pbkdf2`, `sha2` | Key derivation |
| `rand` | Secure random number generation |
| `serde`, `serde_json` | Serialization/deserialization |
| `chrono` | Date/time handling |
| `arboard` | Cross-platform clipboard access |
| `rfd` | Native file dialogs |
| `zeroize` | Secure memory wiping |

## Installation

### Prerequisites

1. **Rust toolchain** (1.70 or later recommended)
   ```bash
   # Install Rust via rustup
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. **Platform-specific dependencies** (see below)

### Building on Linux

#### Dependencies (Debian/Ubuntu)
```bash
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev \
    libxkbcommon-dev libwayland-dev libxcb1-dev \
    libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev
```

#### Dependencies (Fedora/RHEL)
```bash
sudo dnf install -y gcc pkg-config openssl-devel \
    libxkbcommon-devel wayland-devel libxcb-devel
```

#### Dependencies (Arch Linux)
```bash
sudo pacman -S base-devel openssl libxkbcommon wayland libxcb
```

#### Build
```bash
git clone https://github.com/yourusername/RustPW.git
cd RustPW
cargo build --release
```

The binary will be at `target/release/rustpw`.

#### Desktop Integration (Optional)
```bash
# Copy binary to a location in PATH
sudo cp target/release/rustpw /usr/local/bin/

# Copy icon
sudo cp assets/icon.png /usr/share/icons/hicolor/256x256/apps/rustpw.png

# Create desktop entry
cat > ~/.local/share/applications/rustpw.desktop << EOF
[Desktop Entry]
Name=RustPW
Comment=Secure Password Manager
Exec=rustpw
Icon=rustpw
Terminal=false
Type=Application
Categories=Utility;Security;
EOF
```

### Building on Windows

#### Prerequisites
1. Install [Rust](https://rustup.rs/) (use the Windows installer)
2. Install [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) with "Desktop development with C++"

#### Build
```powershell
git clone https://github.com/yourusername/RustPW.git
cd RustPW
cargo build --release
```

The executable will be at `target\release\rustpw.exe`.

**Note**: The application is built with `#![windows_subsystem = "windows"]` so no console window appears when running from Explorer.

#### Creating Windows Installer (Optional)

You can use tools like [Inno Setup](https://jrsoftware.org/isinfo.php) or [WiX](https://wixtoolset.org/) to create an installer.

### Building on macOS

#### Prerequisites
1. Install Xcode Command Line Tools:
   ```bash
   xcode-select --install
   ```
2. Install Rust:
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

#### Build
```bash
git clone https://github.com/yourusername/RustPW.git
cd RustPW
cargo build --release
```

The binary will be at `target/release/rustpw`.

#### Creating macOS App Bundle (Optional)
```bash
mkdir -p RustPW.app/Contents/MacOS
mkdir -p RustPW.app/Contents/Resources
cp target/release/rustpw RustPW.app/Contents/MacOS/
cp assets/icon.png RustPW.app/Contents/Resources/

cat > RustPW.app/Contents/Info.plist << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>rustpw</string>
    <key>CFBundleIdentifier</key>
    <string>com.rustpw.app</string>
    <key>CFBundleName</key>
    <string>RustPW</string>
    <key>CFBundleVersion</key>
    <string>1.0.0</string>
    <key>CFBundleIconFile</key>
    <string>icon.png</string>
</dict>
</plist>
EOF
```

## Usage

### Creating a Vault

1. Launch RustPW
2. Click **"New Vault"** on the startup screen or toolbar
3. Click **"Browse"** to select a location and filename (use `.rustpw` extension)
4. Enter a strong passphrase and confirm it
5. Click **"Create"**

### Opening a Vault

1. Click **"Open Vault"** on the startup screen or toolbar
2. Browse to select your `.rustpw` file
3. Enter your passphrase
4. Click **"Open"**

### Managing Entries

#### Adding an Entry
1. Select a category from the tabs (or create one first)
2. Click **"Add Entry"** in the toolbar
3. Fill in the entry details:
   - **Title**: Name of the entry (required)
   - **Username**: Login username
   - **Password**: Click "Gen" to generate a password
   - **URL**: Website or service URL
   - **Notes**: Additional information
4. Click **"Add"**

#### Editing an Entry
- Click the **"Edit"** button on any entry row

#### Deleting an Entry
- Click the **"Del"** button on any entry row

#### Viewing/Copying Passwords
- Click **"Eye"** to toggle password visibility
- Click **"Copy"** to copy password to clipboard (auto-clears after configured time)

### Managing Categories

#### Adding a Category
- Click **"Add Category"** in the toolbar

#### Renaming a Category
- **Double-click** on a category tab to rename it

#### Deleting a Category
- Click the **"x"** button on a category tab (deletes all entries in that category)

### Password Generator

1. Click **"Password Gen"** in the toolbar
2. Configure options:
   - **Length**: Password length (slider)
   - **Uppercase**: Include A-Z
   - **Lowercase**: Include a-z
   - **Digits**: Include 0-9
   - **Special**: Include symbols (!@#$%^&*...)
   - **Exclude Ambiguous**: Remove similar characters (0/O, 1/l/I)
3. Click **"Regenerate"** to create a new password
4. Click **"Copy"** to copy to clipboard

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Enter` | Confirm dialog / Submit form |
| `Escape` | Close dialog / Cancel |

## Configuration

Configuration is stored in `rustpw.conf` (JSON format) in the same directory as the executable.

### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `aes_mode` | Cipher mode: "GCM", "CBC", or "CTR" | "GCM" |
| `aes_key_size` | Key size in bits (256 only) | 256 |
| `pbkdf2_iterations` | PBKDF2 iteration count | 100,000 |
| `auto_lock_minutes` | Auto-lock after inactivity (minutes) | 5 |
| `clipboard_clear_seconds` | Clear clipboard after (seconds) | 30 |
| `default_password_length` | Default generated password length | 16 |
| `max_category_name_length` | Maximum category name length | 30 |
| `default_vault` | Path to default vault (auto-open on startup) | null |

### Example Configuration

```json
{
  "aes_mode": "GCM",
  "aes_key_size": 256,
  "pbkdf2_iterations": 100000,
  "auto_lock_minutes": 5,
  "clipboard_clear_seconds": 30,
  "default_password_length": 16,
  "max_category_name_length": 30,
  "default_vault": "/home/user/Documents/vault.rustpw"
}
```

### Accessing Configuration

Click **"Config"** in the toolbar to open the configuration dialog. You can use the **"Browse"** button next to the default vault field to select a vault file using the native file dialog.

### Important Note on Cipher Mode

The cipher mode setting in configuration only applies when **creating new vaults**. When opening an existing vault, the cipher mode is read from the vault file header. This means:

- You can open any vault regardless of your current cipher mode setting
- Different vaults can use different cipher modes
- Changing the cipher mode in config won't affect existing vaults

## Vault File Format

RustPW vault files (`.rustpw`) use a binary format:

```
┌─────────────────────────────────────────────────────────────┐
│                      File Structure                          │
├──────────────────┬──────────────────────────────────────────┤
│ Offset (bytes)   │ Content                                  │
├──────────────────┼──────────────────────────────────────────┤
│ 0                │ Version (1 byte)                         │
│ 1                │ Cipher Mode (1 byte): 0=CBC, 1=CTR, 2=GCM│
│ 2-3              │ Key Size (2 bytes, big-endian)           │
│ 4-7              │ PBKDF2 Iterations (4 bytes, big-endian)  │
│ 8-23             │ Salt (16 bytes)                          │
│ 24-35            │ Nonce/IV (12 bytes)                      │
│ 36+              │ Encrypted JSON payload + Auth Tag (GCM)  │
└──────────────────┴──────────────────────────────────────────┘
```

### Encrypted Payload Structure (JSON)

```json
{
  "categories": {
    "Category Name": [
      {
        "title": "Entry Title",
        "username": "user@example.com",
        "password": "secret123",
        "url": "https://example.com",
        "notes": "Additional notes",
        "created": "2024-01-01T00:00:00Z",
        "modified": "2024-01-01T00:00:00Z"
      }
    ]
  },
  "created": "2024-01-01T00:00:00Z",
  "modified": "2024-01-01T00:00:00Z"
}
```

## Security Model

### Encryption

- **Algorithm**: AES-256 (256-bit key)
- **Modes**:
  - **GCM** (recommended): Authenticated encryption with integrity verification
  - **CTR**: Stream cipher mode
  - **CBC**: Block cipher mode with PKCS7 padding

### Key Derivation

- **Algorithm**: PBKDF2-HMAC-SHA256
- **Salt**: 16 bytes, randomly generated per vault
- **Iterations**: Configurable (default: 100,000)

### Security Features

| Feature | Description |
|---------|-------------|
| **Memory Zeroization** | Sensitive data (passphrase, decrypted vault) is securely wiped from memory when the vault is locked |
| **Auto-Lock** | Vault automatically locks after configurable inactivity period |
| **Clipboard Auto-Clear** | Copied passwords are automatically cleared from clipboard |
| **No Plain-Text Storage** | Passwords are never stored in plain text on disk |
| **Authenticated Encryption** | GCM mode provides integrity verification, detecting tampering |
| **Atomic Saves with Backup** | Vault saves use atomic writes to prevent corruption (see below) |

### Corruption Prevention

RustPW uses **atomic writes with automatic backup** to prevent vault corruption:

1. **Write to temp file** - Data is first written to `vault.rustpw.tmp`
2. **Create backup** - The existing vault is renamed to `vault.rustpw.bak`
3. **Atomic rename** - The temp file is renamed to the actual vault (atomic operation)

This ensures:
- If power fails during write, the original vault remains intact
- If the save fails for any reason, you have a `.bak` backup
- The vault file is never in a partially-written state

**Recovery**: If your vault becomes corrupted, check for a `.bak` file in the same directory and rename it to restore your previous version.

### Recommendations

1. **Use GCM mode** for authenticated encryption
2. **Use a strong passphrase** (16+ characters with mixed case, numbers, symbols)
3. **Keep iterations high** (100,000+) to slow brute-force attacks
4. **Enable auto-lock** when stepping away from your computer
5. **Keep backups** of your vault file in a secure location

## Troubleshooting

### Common Issues

**"Invalid vault file" error**
- Ensure you're opening a valid `.rustpw` file
- The file may be corrupted or from an incompatible version

**"Decryption failed" error**
- Verify you're entering the correct passphrase
- Check caps lock is not accidentally enabled

**Application won't start on Linux**
- Ensure Wayland/X11 libraries are installed
- Try running from terminal to see error messages

**Icons not displaying on Windows**
- Ensure `assets/icon.ico` exists when building
- Rebuild with `cargo clean && cargo build --release`

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Built with [Iced](https://github.com/iced-rs/iced) - A cross-platform GUI library for Rust
- Encryption provided by [RustCrypto](https://github.com/RustCrypto) crates
- Inspired by various open-source password managers

---

**Disclaimer**: While RustPW implements strong encryption, no software is 100% secure. Use at your own risk and always maintain backups of important data.
