#!/system/bin/sh
# Force an installed package's primaryCpuAbi to x86_64 in packages.xml so the
# process runs x86_64 native on an x86_64 emulator (matching the native
# libjiagu_x64.so), WITHOUT re-signing the APK (keeps 360 anti-tamper happy).
# Run as root, then `adb reboot`. Usage: sh edit_abi.sh <package>   (or edit PKG)
PKG="${1:-com.gentle.ppcat}"
XML=/data/system/packages.xml
echo "=== before ==="
grep -o "name=\"$PKG\"[^>]*primaryCpuAbi=\"[^\"]*\"" $XML | head -1
cp $XML ${XML}.bak
sed -i "/name=\"$PKG\"/ s/primaryCpuAbi=\"arm64-v8a\"/primaryCpuAbi=\"x86_64\"/" $XML
sed -i "/name=\"$PKG\"/ s/primaryCpuAbi=\"armeabi-v7a\"/primaryCpuAbi=\"x86_64\"/" $XML
echo "=== after (reboot for PMS to apply) ==="
grep -o "$PKG[^>]*primaryCpuAbi=\"[^\"]*\"" $XML | head -1
