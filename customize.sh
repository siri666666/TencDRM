SKIPUNZIP=0

# ---------- TencDRM installer ----------
# based on 阿灵's Tenc-ano_tmp installer, cleaned:
#   * removed Telegram promo / auto-open
#   * removed hard-coded expiry
#   * supports both KernelSU / APatch / Magisk

ui_print "- TencDRM v1.0.0 (opensource rewrite)"

ABI=$(getprop ro.product.cpu.abi)
case "$ABI" in
  arm64*) ;;
  *) ui_print "! 仅支持 arm64 设备, 当前: $ABI"; abort "! 安装已终止";;
esac

# remove legacy original-module copies to avoid conflicts
rm -rf /data/adb/modules/*ano_tmp 2>/dev/null

set_perm_recursive "$MODDIR" 0 0 0755 0644
for b in DRMID-inject DRMID-A.so DRMID-B.so; do
  set_perm "$MODDIR/prebuilt/$b" 0 0 0755 0644
done
set_perm "$MODDIR/service.sh"  0 0 0755 0744
set_perm "$MODDIR/post-fs-data.sh" 0 0 0755 0744
set_perm "$MODDIR/config.prop" 0 0 0600 0600

# per-device random salt for the fake DRM ID (kept secret on device)
if [ ! -s "$MODDIR/prebuilt/DRMID" ]; then
  SALT=$(tr -dc 'a-f0-9' < /dev/urandom 2>/dev/null | head -c 64)
  [ -n "$SALT" ] || SALT=$(date +%s%N | sha256sum 2>/dev/null | cut -c1-64)
  printf '%s' "$SALT" > "$MODDIR/prebuilt/DRMID"
fi
chmod 600 "$MODDIR/prebuilt/DRMID" 2>/dev/null
ui_print "- DRMID 伪装: 已生成本机专属随机盐值"

# auto-detect Widevine DRM HAL channel: aidl (Android 12+) or hidl (legacy)
DRMFMT=$(cat /vendor/etc/vintf/manifest.xml /vendor/etc/vintf/manifest/*.xml 2>/dev/null | awk '
  /<hal format="/ { f = ($0 ~ /aidl/) ? "aidl" : "hidl" }
  /IDrmFactory\/widevine/ { print f; exit }
')
if [ -z "$DRMFMT" ]; then
  if [ -f /vendor/lib64/libwvaidl.so ] || [ -f /vendor/lib/libwvaidl.so ]; then
    DRMFMT=aidl
  elif [ -f /vendor/lib64/libwvhidl.so ] || [ -f /vendor/lib/libwvhidl.so ]; then
    DRMFMT=hidl
  fi
fi
case "$DRMFMT" in
  hidl) DRMSCHEME=B ;;
  *)    DRMFMT=aidl; DRMSCHEME=A ;;
esac
sed -i "s/^DRMID方案=.*/DRMID方案=$DRMSCHEME/" "$MODDIR/config.prop" 2>/dev/null
ui_print "- DRMID 伪装: 检测到 $DRMFMT 通道, 默认启用 $DRMSCHEME 方案"

ui_print "- 原模块: 阿灵 (TG @Whitelist520) · 本仓库仅做开源重制"
ui_print "- 配置文件: /data/adb/modules/TencDRM/config.prop"
