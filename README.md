# WUPify

WUPify is a simple batch tool for cleaning and preparing **No-Intro Wii U CDN folders** for **WUP Installer** and **Cemu**.

**Cemu can use the prepared folders directly**, so there is no need to decrypt them first. The same prepared folders can also be copied to your Wii U SD card for installation with **WUP Installer**.

## Dependencies

- Python 3.10+
- `cryptography`

On Windows, `Launch WUPify.bat` automatically installs `cryptography` if it is missing.

## How to use

### Windows

Put these files in the main folder of your Wii U CDN collection:

```text
WUPify.py
Launch WUPify.bat
```

Then double-click:

```text
Launch WUPify.bat
```

WUPify scans the subfolders recursively and prepares the titles it finds.

### Command line

```bash
python WUPify.py --path . --recursive
```

Preview the changes without modifying any files:

```bash
python WUPify.py --path . --recursive --dry-run
```

Use `python WUPify.py --help` to see the available options.

## Usage

- **Cemu:** use the prepared title folder directly.
- **WUP Installer:** copy the prepared title folder to `SD:\install\` on your Wii U SD card.

A prepared title folder uses the standard WUP layout:

```text
00000000.app
00000001.app
...
title.tmd
title.tik
title.cert
```

WUPify leaves titles that are already ready untouched and reports any title it cannot prepare safely.

## Credits

Parts of WUPify are based on [WiiUDownloader](https://github.com/Xpl0itU/WiiUDownloader) by Xpl0itU.

WiiUDownloader is licensed under the GNU General Public License v3.0. WUPify is distributed under the GNU General Public License v3.0 as well. See `LICENSE`.
