/*
 * drm_parcel_hook.c — TencDRM 方案 A (AIDL) 钩子库
 * 重建自原模块 DRMID-A.so 的行为 (DRMID_parcel.c, 符号名保留)。
 *
 * 注入进 Widevine DRM HAL 进程后由构造函数自动初始化:
 *   1. dlsym 取 libbinder_ndk 的 AParcel_readString / AParcel_writeByteArray
 *   2. dl_iterate_phdr 定位 libbinder_ndk 的 GOT, 经 /proc/self/mem 把槽位
 *      改写为 my_readString / my_writeByteArray
 *   3. HAL 读取属性名 "provisioningUniqueId"/"deviceUniqueId" 时点亮线程门控,
 *      紧随其后的 writeByteArray 把调用方缓冲区替换为
 *      persist.vendor.wvid 属性中 hex 解码出的 32 字节伪装 ID
 *
 * 伪装 ID: service.sh 启动时执行 setprop persist.vendor.wvid <64位hex盐值>
 */
#define LOG_TAG "DRMID"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <link.h>
#include <pthread.h>
#include <sys/system_properties.h>
#include <android/log.h>

#define PROP_ID   "persist.vendor.wvid"
#define SPOOF_LEN 32

typedef void  (*writeByteArray_t)(const void *, const uint8_t *, int32_t);
typedef void *(*readString_t)(const void *, void *, void *, void *, void *, void *);

static void *real_readString;
static void *real_writeByteArray;
static int   fd_mem = -1;
static volatile int n_read_total, n_write_total;

static __thread int  t_gate;            /* 线程门控 */
static __thread char t_name[64];        /* readString 捕获的属性名 */

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static void lg(const char *fmt, ...)
{
    static void (*vprint)(int, const char *, const char *, va_list);
    static int tried;
    va_list ap;
    if (!vprint && !tried) {
        tried = 1;
        void *h = dlopen("liblog.so", RTLD_NOW);
        if (h) vprint = dlsym(h, "__android_log_vprint");
    }
    if (!vprint) return;
    va_start(ap, fmt);
    vprint(ANDROID_LOG_INFO, LOG_TAG, fmt, ap);
    va_end(ap);
}

static void mem_poke(unsigned long addr, const void *buf, size_t len)
{
    if (fd_mem < 0) fd_mem = open("/proc/self/mem", O_RDWR);
    if (fd_mem < 0) return;
    lseek(fd_mem, (off_t)addr, SEEK_SET);
    if (write(fd_mem, buf, len) < 0) { /* 竞态时静默重试由外层循环兜底 */ }
}

/* my_stringAlloc: 透传 malloc, 捕获 HAL 读取到的属性名 */
static void *my_stringAlloc(void *ctx, const char *s, size_t len)
{
    uint8_t *buf = malloc(len + 1);
    if (!buf) abort();
    memcpy(buf, s, len);
    buf[len] = '\0';
    if (len < sizeof(t_name) - 1) {
        memcpy(t_name, s, len);
        t_name[len] = '\0';
    } else {
        t_name[0] = '\0';
    }
    return buf;
}

/* my_readString: 放行真实读取, 命中属性名则武装门控 */
static void *my_readString(const void *p, void *a1, void *a2,
                           void *a3, void *a4, void *a5)
{
    void *res;
    t_gate = 0;
    t_name[0] = '\0';
    res = ((readString_t)real_readString)(p, a1, (void *)my_stringAlloc,
                                          a3, a4, a5);
    t_gate = 0;
    if (res && t_name[0] &&
        (strcmp(t_name, "provisioningUniqueId") == 0 ||
         strcmp(t_name, "deviceUniqueId") == 0)) {
        t_gate = 1;
        n_read_total++;
    }
    return res;
}

/* my_writeByteArray: 门控命中时把伪装 ID 写入调用方缓冲后再放行 */
static void my_writeByteArray(const void *p, const uint8_t *arr,
                              int32_t len, void *a3, void *a4, void *a5)
{
    char prop[PROP_VALUE_MAX];
    int  plen, gate = t_gate;

    t_gate = 0;                              /* 一次性消费 */
    if (gate && arr && len > 0) {
        memset(prop, 0, sizeof(prop));
        plen = __system_property_get(PROP_ID, prop);
        if (plen >= 2) {
            uint8_t fake[SPOOF_LEN];
            int pairs = (plen - 2) / 2;
            if (pairs > SPOOF_LEN) pairs = SPOOF_LEN;
            int ok = 1;
            for (int i = 0; i < pairs && ok; i++) {
                int hi = hexval(prop[1 + i * 2]);
                int lo = hexval(prop[2 + i * 2]);
                if (hi < 0 || lo < 0) { ok = 0; break; }
                fake[i] = (uint8_t)((hi << 4) | lo);
            }
            if (ok && pairs > 0) {
                memcpy((void *)arr, fake, SPOOF_LEN);
                n_write_total++;
                lg("spoof: 32B device id replaced (prop %d bytes)", plen);
            }
        }
    }
    ((writeByteArray_t)real_writeByteArray)(p, arr, len);
}

/* 定位 libbinder_ndk 的 GOT 槽位并补丁 */
static void patch_libbinder_ndk(unsigned long base, long phnum,
                                const ElfW(Phdr) *phdr)
{
    ElfW(Dyn) *dyn = 0;
    unsigned long got = 0;
    int pr = 0, pw = 0;

    for (long i = 0; i < phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            dyn = (ElfW(Dyn) *)(base + phdr[i].p_vaddr);
            break;
        }
    }
    if (!dyn) return;
    for (; dyn->d_tag; dyn++) {
        if (dyn->d_tag == DT_PLTGOT) { got = dyn->d_un.d_ptr; break; }
    }
    if (!got) return;

    for (unsigned long *slot = (unsigned long *)got + 3; *slot; slot++) {
        if ((unsigned long)real_readString == *slot && !pr) {
            void *my = (void *)my_readString;
            mem_poke((unsigned long)slot, &my, sizeof(my));
            pr = 1;
        } else if ((unsigned long)real_writeByteArray == *slot && !pw) {
            void *my = (void *)my_writeByteArray;
            mem_poke((unsigned long)slot, &my, sizeof(my));
            pw = 1;
        }
    }
    lg("patched GOT: readString x%d, writeByteArray x%d", pr, pw);
}

static int phdr_cb(struct dl_phdr_info *info, size_t size, void *data)
{
    (void)size; (void)data;
    const char *nm = info->dlpi_name ? info->dlpi_name : "";
    if (!strstr(nm, "libbinder_ndk.so"))
        return 0;
    patch_libbinder_ndk(info->dlpi_addr, info->dlpi_phnum, info->dlpi_phdr);
    return 1;                                /* 已处理, 停止遍历 */
}

__attribute__((constructor))
static void drm_parcel_hook_init(void)
{
    void *h;

    h = dlopen("liblog.so", RTLD_NOW);
    (void)h;

    h = dlopen("libbinder_ndk.so", RTLD_NOW);
    if (!h) { lg("init: libbinder_ndk not mapped"); return; }

    real_readString     = dlsym(h, "AParcel_readString");
    real_writeByteArray = dlsym(h, "AParcel_writeByteArray");
    if (!real_readString || !real_writeByteArray) {
        lg("init: parcel symbols missing");
        return;
    }
    lg("init: hooks armed, targeting GOT of libbinder_ndk");
    dl_iterate_phdr(phdr_cb, 0);
}
