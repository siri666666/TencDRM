# TencDRM

**Tencent 游戏 DRMID 伪装 / 设备标记清理模块**（KernelSU / APatch / Magisk 通用，仅 arm64）

完全开源：shell 层为可读脚本，二进制组件全部由 `src/` 源码经 GitHub Actions（官方 NDK）构建，可复现、无黑盒、无到期开关、无推广行为。

---

## 工作原理

腾讯游戏通过 Widevine DRM 的 `provisioningUniqueId`（媒体 DRM 供应唯一 ID）生成设备标记
（DRMID），该标记与硬件绑定、刷机不灭。

本模块在检测到受支持的游戏运行时：

1. 用 ptrace 注入器把 `DRMID-A.so`（AIDL 通道）或 `DRMID-B.so`（HIDL 通道）
   注入 Widevine DRM HAL 进程；
2. 钩子拦截 binder parcel 中的 `provisioningUniqueId` 字段，
   替换为安装时生成的**每台设备唯一的盐值派生 ID**；
3. 游戏侧查询到的设备 ID 与真机历史标记断开，实现"设备标记解决 / 换新设备"效果。

配套功能（均可配置开关）：

| 功能 | 说明 |
|---|---|
| 解决设备标记 | 开机收紧设备标记相关文件权限（post-fs-data 阶段） |
| KILL进程 | 游戏运行时强杀 KILL_LIST 内应用（root 管理器/工具类） |
| USB调试关闭 | 游戏运行时关闭 USB 调试（**默认关闭**此功能） |
| rm-rf_FILE | 游戏运行时删除指定目录 |
| CPU 伪装 | 游戏运行时 bind-mount 伪装 `/proc/cpuinfo`（实验性） |
| 息屏休眠 | 熄屏时挂起守护循环降低功耗 |
| 多用户 | 兼容 0~999 全部用户分身 |

## 安装

从 [Releases](https://github.com/siri666666/TencDRM/releases) 或
[Actions 构建产物](https://github.com/siri666666/TencDRM/actions) 下载 `TencDRM.zip`
（CI 用官方 NDK 从 `src/` 构建，可复现），管理器刷入或：

```
su -c magisk --install-module TencDRM.zip   # Magisk
ksud module install TencDRM.zip             # KernelSU
```

## 构建（完全开源，无预编译黑盒）

```bash
make NDK=/path/to/android-ndk-r26d   # 产出 out/ 下的注入器与两个钩子库
```

或直接推送触发 GitHub Actions 自动构建（`.github/workflows/build.yml`）。
`prebuilt/DRMID`（64 位 hex 盐值）由安装器在设备上随机生成，不入库。

## 配置

`/data/adb/modules/TencDRM/config.prop`，每 3 秒热重读，改完即生效：

| 键 | 默认 | 说明 |
|---|---|---|
| `GAME_LIST` | 主流腾讯游戏 | 监听的游戏包名（空格分隔），触发器 |
| `DRMID伪装` | 开启 | DRM 钩子注入总开关 |
| `DRMID方案` | 安装时自动探测 | A=AIDL / B=HIDL，异常时可切换 |
| `解决设备标记` | 开启 | 开机收紧标记文件权限 |
| `KILL进程` / `KILL_LIST` | 开启 | 游戏运行时强杀列表内应用 |
| `USB调试关闭` | **关闭** | 游戏运行时关 USB 调试（不自动恢复） |
| `rm-rf_FILE` | 空 | 游戏运行时删除的目录 |
| `CPU伪装` / `CPU_LIST` | 关闭 | cpuinfo 挂载伪装（实验性） |
| `息屏休眠` | 开启 | 熄屏降功耗 |

## 验证

已在 OnePlus Pad 2 Pro (OPD2404 / ColorOS 16 / 内核 6.1) 实测:
注入器成功将钩子库加载进 Widevine DRM HAL 进程, 钩子完成 libbinder_ndk 的 GOT
补丁 (logcat `DRMID: init: hooks armed`), HAL 进程稳定无崩溃。

功能级验证: 安装 `com.liuzh.deviceinfo`（设备信息检测器），开启任意 GAME_LIST
游戏后回到检测器查看 DRM ID 是否已变化。

## 免责声明

- 本模块通过伪造 DRM 设备身份对抗游戏风控，属于灰色地带的设备指纹对抗工具；
- 仅限在自己的设备上学习研究使用，使用本模块产生的任何账号后果自行承担；
- 伪装身份与 keybox 一样具有唯一性，**不要外传设备上的 `prebuilt/DRMID` 盐值文件**；
- 不要用于任何作弊行为。

## License

[MIT](LICENSE)
