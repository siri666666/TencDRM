#!/system/bin/sh
#
# TencDRM — Tencent 游戏 DRMID 伪装守护 (开源重制版)
# 逻辑来自对原模块 (阿灵 / TG @Whitelist520) 的逆向还原, 见 README
#

MODDIR=${0%/*}
CFG="$MODDIR/config.prop"
PRE="$MODDIR/prebuilt"

cfg() {
    sed -n "s/^$1=//p" "$CFG" 2>/dev/null | head -n 1 | tr -d '\r'
}
cfg_on() {
    [ "$(cfg "$1")" = "开启" ]
}

SCHEME=$(cfg DRMID方案)
case "$SCHEME" in
  B|b) SCHEME=B ;;
  *)   SCHEME=A ;;
esac

# 等待用户解锁 (解锁前 DRM HAL / am 不可用)
# 纯 shell 实现: dumpsys trust 的 deviceLocked 字段 (无安全锁的设备恒为 0, 直接放行)
while dumpsys trust 2>/dev/null | grep -q 'deviceLocked=1'; do
    sleep 2
done

# 清理上一次注入残留的 ano_tmp 缓存 (全部用户/分身)
rm -rf /data/data/*/files/ano_tmp /data/user/*/*/files/ano_tmp 2>/dev/null

GAME_ON=0

while true; do
    # ---- 息屏休眠: 熄屏时挂起大部分工作 ----
    if cfg_on 息屏休眠; then
        if dumpsys power 2>/dev/null | grep -q 'mWakefulness=Asleep'; then
            sleep 5
            continue
        fi
    fi

    # ---- 每轮重读配置 (改配置即时生效, 无需重启) ----
    KILL_PROC=$(cfg KILL进程)
    KILL_LIST=$(cfg KILL_LIST)
    USB_OFF=$(cfg USB调试关闭)
    RM_LIST=$(cfg rm-rf_FILE)
    CPU_SPOOF=$(cfg CPU伪装)
    CPU_LIST=$(cfg CPU_LIST)
    GAME_LIST=$(cfg GAME_LIST)

    # ---- 游戏进程检测 ----
    GAME=""
    for g in $GAME_LIST; do
        [ -z "$g" ] && continue
        if pgrep -f "$g" >/dev/null 2>&1; then
            GAME="$g"
            break
        fi
    done

    # ---- 游戏启动: 环境处理 (边沿触发, 一次) ----
    if [ -n "$GAME" ] && [ "$GAME_ON" = "0" ]; then
        GAME_ON=1
        if [ "$KILL_PROC" = "开启" ]; then
            for k in $KILL_LIST; do
                [ -n "$k" ] && am force-stop "$k" 2>/dev/null
            done
        fi
        # 注意: 与原版一致, 关闭后不会自动恢复
        if [ "$USB_OFF" = "开启" ]; then
            settings put global adb_enabled 0
        fi
        for p in $RM_LIST; do
            [ -n "$p" ] && rm -rf "$p" 2>/dev/null
        done
        if [ "$CPU_SPOOF" = "开启" ]; then
            for g2 in $CPU_LIST; do
                if [ "$g2" = "$GAME" ]; then
                    mount --bind "$MODDIR/cpuinfo.txt" /proc/cpuinfo 2>/dev/null
                fi
            done
        fi
    fi

    # ---- 游戏停止: 还原 (边沿触发) ----
    if [ -z "$GAME" ] && [ "$GAME_ON" = "1" ]; then
        GAME_ON=0
        if [ "$CPU_SPOOF" = "开启" ]; then
            umount /proc/cpuinfo 2>/dev/null
        fi
    fi

    # ---- DRM 注入: 扫描 Widevine DRM HAL 进程 ----
    for p in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
        e=$(readlink /proc/$p/exe 2>/dev/null) || continue
        case "$e" in
            */android.hardware.drm*widevine*|*/mediadrmserver)
                # 已注入 (maps 含标记) 则跳过
                grep -q "DRMID-A" /proc/$p/maps 2>/dev/null && continue
                so=/data/local/tmp/DRMID_${SCHEME}_$p.so
                cp "$PRE/DRMID-$SCHEME.so" "$so" 2>/dev/null
                chmod 755 "$so" 2>/dev/null
                chcon u:object_r:shell_data_file:s0 "$so" 2>/dev/null
                "$PRE/DRMID-inject" "$p" "$so" 2>/dev/null
                ;;
        esac
    done

    sleep 3
done
