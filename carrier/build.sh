#!/bin/bash
# =============================================================================
#  AppLock+ 载体包构建（WSL / Linux）
#
#    wsl -d Ubuntu-22.04 -- bash /mnt/d/WorkBudy/iOS-Tweaks/AppLockPlus/carrier/build.sh
#
#  产物：com.applockplus.refactored_0.4.2-1_iphoneos-arm64e.deb
#
#  说明：这是「载体包」——只把 AppLockPlus.dylib 放到设备上，供 Debs/Filza 导出后
#  用 TrollFools/JailFools 按应用注入。它不是 SpringBoard 插件，不依赖 substrate。
# =============================================================================
set -euo pipefail

SRC=/mnt/d/WorkBudy/iOS-Tweaks/AppLockPlus/carrier
DYLSRC="/mnt/d/WorkBudy/iOS-Tweaks/AppLockPlus/AppLockPlus.dylib"
OUT=/mnt/d/WorkBudy/iOS-Tweaks/release/com.applockplus.refactored_0.4.2-1_iphoneos-arm64e.deb

[ -f "$DYLSRC" ] || { echo "!! 找不到 $DYLSRC（先在 applock-plus 里 make）"; exit 1; }

cp -f "$DYLSRC" "$SRC/usr/lib/AppLockPlus/AppLockPlus.dylib"

WORK="$HOME/apl_pkg"
rm -rf "$WORK"; mkdir -p "$WORK"
cp -r "$SRC"/. "$WORK"/
cd "$WORK"
find . -type f \( -name control -o -name postinst -o -name "*.txt" \) -exec sed -i 's/\r$//' {} \;

chmod 755 DEBIAN/postinst
chmod 644 DEBIAN/control usr/lib/AppLockPlus/AppLockPlus.dylib usr/lib/AppLockPlus/README.txt
chmod 755 usr/lib/AppLockPlus

rm -f com.applockplus.refactored_*.deb
dpkg-deb -b -Zxz . "$OUT"
echo "=== 产物 ==="
ls -lh "$OUT"
dpkg-deb -I "$OUT" | sed -n '1,12p'
dpkg-deb -c "$OUT"
