# RustPw MSI Installer

This repository contains the files needed to create a Windows MSI installer for the RustPw application.

## Prerequisites

Before you can build the MSI installer, you need to install WiX Toolset on your system.

### Installing WiX Toolset

Open PowerShell or Command Prompt as Administrator and run:

```bash
winget install WiXToolset.WiX --accept-package-agreements --accept-source-agreements
```

Alternatively, you can download WiX Toolset directly from [https://wixtoolset.org/](https://wixtoolset.org/)

### Verify Installation

After installation, verify WiX is installed correctly:

```bash
wix --version
```

You should see output showing the WiX Toolset version (e.g., 6.0.2 or later).

## Repository Contents

- `rustpw.exe` - The RustPw application executable (~13 MB, x64)
- `Product.wxs` - WiX source file that defines the installer structure
- `License.rtf` - License agreement shown during installation
- `CLAUDE.md` - Project instructions and context

## Building the MSI Installer

### Quick Build

To build the MSI installer, follow these steps:

1. **Open PowerShell or Command Prompt**

2. **Navigate to the project directory:**
   ```powershell
   cd E:\GitHub\RustPw-Install
   ```
   (Replace with your actual path to this repository)

3. **Run the build command:**
   ```powershell
   wix build Product.wxs -o RustPw-Installer.msi -arch x64 -ext WixToolset.UI.wixext -ext WixToolset.Util.wixext
   ```

4. **Wait for completion** - The build process typically takes just a few seconds.

5. **Verify the output:**
   ```powershell
   dir RustPw-Installer.msi
   ```

You should now have a `RustPw-Installer.msi` file (approximately 4-5 MB) ready for distribution.

### Command Breakdown

Let's break down what each part of the build command does:

```powershell
wix build Product.wxs -o RustPw-Installer.msi -arch x64 -ext WixToolset.UI.wixext -ext WixToolset.Util.wixext
```

- **`wix build`** - The WiX command to build an installer package
- **`Product.wxs`** - Input file: WiX source XML that defines the installer
- **`-o RustPw-Installer.msi`** - Output file: The name of the MSI installer to create
- **`-arch x64`** - Target architecture: 64-bit (installs to `C:\Program Files`)
  - Without this flag, it would install to `C:\Program Files (x86)`
- **`-ext WixToolset.UI.wixext`** - Extension: Enables installer UI dialogs and wizard
- **`-ext WixToolset.Util.wixext`** - Extension: Enables utility features like PermissionEx

## Installer Features

The generated MSI installer includes:

- **Installation Directory:** `C:\Program Files\RustPw`
- **Start Menu Shortcut:** Creates a "RustPw" shortcut in the Start Menu
- **File Association:** Associates `.rustpw` file extension with the application
- **Uninstaller:** Automatic uninstall capability via Windows Settings
- **User Permissions:** Grants full control to regular users in the installation folder
- **Upgrade Support:** Handles major upgrades and prevents downgrades

## Installation Process

When users run the MSI installer, they will:

1. See the license agreement (from `License.rtf`)
2. Choose the installation directory (default: `C:\Program Files\RustPw`)
3. Confirm installation
4. Have the application installed with Start Menu shortcuts

## Updating the Installer

If you update `rustpw.exe` and need to rebuild the MSI:

1. Replace the `rustpw.exe` file in this directory with the new version
2. Run the build command again:
   ```powershell
   wix build Product.wxs -o RustPw-Installer.msi -arch x64 -ext WixToolset.UI.wixext -ext WixToolset.Util.wixext
   ```
3. The MSI will be regenerated with the updated executable

### Updating Version Number

If you want to change the version number displayed in Windows:

1. Open `Product.wxs` in a text editor
2. Find line 6: `Version="1.0.0.0"`
3. Change to your desired version (e.g., `Version="1.1.0.0"`)
4. Save the file and rebuild the MSI

## Troubleshooting

### "wix: command not found"

If you get this error, WiX Toolset is not installed or not in your PATH. Try:
- Reinstalling WiX Toolset
- Restarting your terminal after installation
- Running `winget list WiX` to verify installation

### "error WIX0200: unhandled extension element"

This means the required extensions are missing from the build command. Make sure you include:
- `-ext WixToolset.UI.wixext`
- `-ext WixToolset.Util.wixext`

### File Not Found Errors

Make sure all required files are in the same directory:
- `rustpw.exe`
- `Product.wxs`
- `License.rtf`

## Security Note

The installer grants full write permissions to regular users in the `C:\Program Files\RustPw` directory. This is configured in `Product.wxs` lines 27-30:

```xml
<util:PermissionEx User="Users" GenericAll="yes" />
```

This is unusual for Program Files installations. Consider whether your application truly needs write access to its installation directory, or if it should write data to user-specific locations like `%APPDATA%` instead.

## Technical Details

- **Installer Version:** 500 (Windows Installer 5.0)
- **Architecture:** x64 (64-bit)
- **Scope:** Per-machine installation (requires administrator privileges)
- **Compression:** Cabinet files embedded in MSI
- **Upgrade Code:** `12345678-1234-1234-1234-123456789012` (for identifying the product across versions)

## Additional Resources

- [WiX Toolset Documentation](https://wixtoolset.org/docs/)
- [WiX v4/v6 Schema Reference](https://wixtoolset.org/docs/schema/)
- [Windows Installer Best Practices](https://docs.microsoft.com/en-us/windows/win32/msi/windows-installer-best-practices)

## License

See `License.rtf` for application license terms.
