Android Notes
===

# Android Emulator

## Root emulator and install Magisk

- Enable cold boot
- Install rootAVD and find your ramdisk
```
git clone https://github.com/newbit1/rootAVD.git
cd rootAVD
./rootAVD.sh ListAllAVDs
```

- Patch the ramdisk
```
./rootAVD.sh system-images/android-33/google_apis_playstore/arm64-v8a/ramdisk.img
```

## Install Frida
- Open Magisk
- Reboot
- Download https://github.com/ViRb3/magisk-frida/releases
- Copy zip file to emulator by drag and drop
- Open Magisk and install from storage
- Check if frida is working via `frida-ps -U`
- Start the app

# SSLPinning

## Auto

- [Trust User Certs](https://github.com/lupohan44/TrustUserCertificates)
- Frida 
```
frida -U -l ./frida-script.js -f <identifier>
```

## Manual

If the hooking doesn't work, we need to extract, patch smali code and zip align
- `apktool -d test.apk`
- Patch smali code or change builtin certificates. Search `TrustManager` or `CertificatePinner`
- `apktool b test/ -o modified.apk`
- `zipalign -v 4 modified.apk`
