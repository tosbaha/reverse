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
