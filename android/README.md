Android Notes
===

SSLPinning
--
Auto
--
Xposed + JustTrustMe

Manual
--
If the hooking doesn't work, we need to extract, patch smali code and zip align
- `apktool -d test.apk`
- Patch smali code or change builtin certificates. Search `TrustManager` or `CertificatePinner`
- `apktool b test/ -o modified.apk`
- `zipalign -v 4 modified.apk`

Frida
--
- Download [Frida Server](https://github.com/frida/frida/releases) for Android Emulator, unpack and rename it to `frida-server-android-x86`
- Transfer to Emulator and start it

```bash
adb push frida-server-android-x86  /data/local/tmp/frida-server
adb shell chmod 777  /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &
frida --no-pause -U -l ./frida-script.js -f com.ptt
```
- Find the identifer of the app
```
frida-ps -Ua
```
- Start the app

```
frida --no-pause -U -l ./frida-script.js -f <identifier>
```