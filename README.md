# WUPify

Simple tool to clean and prepare **No-Intro CDN folders** for **WUP Installer** and **Cemu**.

Yes **Cemu** can play it directly, you don't need to decrypt it anymore ! 
You can effectively use the same folders to play with **Cemu** and install directly to your **Wii U**.

---

## How to use

1. Put these files together in the main folder:
   - `WUPify.py`  
   - `Launch WUPify.bat`  
   - `title.cert` *(you need to provide it yourself)*

2. Double-click **Launch WUPify.bat**

It will automatically clean and fix all subfolders.

---

## Notes

- **Cemu:** can play the folders directly (no decryption needed)  
- **WUP Installer:** copy the prepared folders to `SD:\install\` on your Wii U  
- **title.cert** is required and must be next to the script  
- **Expected hash:**  
  - CRC32: `0B80C239`  
  - MD5: `420D5E6BB1BCB09B234F02CF6A6F4597`  
- You can get it with **WiiUDownloader** → *Tools → Generate fake ticket and cert*  
  *(it's the same for all games, updates, and DLCs)*