#!/system/bin/sh
# 解决设备标记: 开机时收紧设备标记相关目录权限 (禁止普通进程读取)
MODDIR=${0%/*}

MARK=$(sed -n "s/^解决设备标记=//p" "$MODDIR/config.prop" 2>/dev/null | head -n 1 | tr -d '\r')
if [ "$MARK" = "开启" ]; then
    chmod 700 /mnt/vendor/persist/data 2>/dev/null
else
    chmod 771 /mnt/vendor/persist/data 2>/dev/null
fi
