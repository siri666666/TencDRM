/*
 * wvhidl_hook.c — TencDRM 方案 B (HIDL) 钩子库
 * TencDRM 方案 B 钩子库。
 *
 * 与方案 A 的差异: 不走 binder parcel, 直接在 libwvhidl.so / libcrypto.so
 * 内定位 Widevine CDM 的设备 ID 函数并以 16 字节 detour 补丁函数入口:
 *
 *   wvcdm::CryptoSession::GetInternalDeviceUniqueId(std::string*)
 *   wvcdm::CryptoSession::GetExternalDeviceUniqueId(std::string*)
 *   wvdrm::hardware::drm::V1_2::widevine::WVDrmPlugin::CdmIdentifierBuilder::
 *       getDeviceUniqueId(std::string*)
 *   wvdrm::hardware::drm::V1_2::widevine::WVDrmPlugin::CdmIdentifierBuilder::
 *       getOemcryptoDeviceId(std::string*)
 *   wvdrm::hardware::drm::V1_2::widevine::WVDrmPlugin::CdmIdentifierBuilder::
 *       getOemcryptoDeviceId(wvcdm::SecurityLevel, std::string*)
 *
 * 补丁后这些函数直接返回 persist.vendor.wvid 属性中的伪装 ID (不再调用原函数),
 * 因此原始 ID 也不会落地。persist.vendor.wvid.real 由外部保存原始值 (预留)。
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

#define PROP_ID       "persist.vendor.wvid"
#define PROP_ID_REAL  "persist.vendor.wvid.real"

/* 目标符号 (Itanium ABI mangled) */
static const char *TARGETS[] = {
    "_ZN5wvcdm13CryptoSession25GetInternalDeviceUniqueIdEPNSt3__112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE",
    "_ZN5wvcdm13CryptoSession25GetExternalDeviceUniqueIdEPNSt3__112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE",
    "_ZN5wvdrm8hardware3drm4V1_28widevine11WVDrmPlugin20CdmIdentifierBuilder17getDeviceUniqueIdEPNSt3__112basic_stringIcNS6_11char_traitsIcEENS6_9allocatorIcEEEE",
    "_ZN5wvdrm8hardware3drm4V1_28widevine11WVDrmPlugin20CdmIdentifierBuilder20getOemcryptoDeviceIdEPNSt3__112basic_stringIcNS6_11char_traitsIcEENS6_9allocatorIcEEEE",
    "_ZN5wvdrm8hardware3drm4V1_28widevine11WVDrmPlugin20CdmIdentifierBuilder20getOemcryptoDeviceIdEN5wvcdm13SecurityLevelEPNSt3__112basic_stringIcNS8_11char_traitsIcEENS8_9allocatorIcEEEE",
};

typedef void *(*string_assign_t)(void *, const char *);
static string_assign_t str_assign;           /* libc++ string::assign(const char*) */
static char fake_id[128];
static int  fd_mem = -1;

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
    write(fd_mem, buf, len);
}

/* 通用 stub: 把输出 std::string 覆写为伪装 ID 后直接返回 (不调用原函数) */
static void stub_common(void *out_str)
{
    if (out_str && str_assign)
        str_assign(out_str, fake_id);
}

/* 各目标共用 stub — 参数布局在 x0/x1/(x2), out 是最后一个参数,
 * 由各 detour 适配 (detour 已把 out 放入 x0 后跳到 stub) */
static void stub_out_x0(void *out) { stub_common(out); }

/* 在内存 ELF 中按符号名查找地址 (libwvhidl 带 dynsym) */
static unsigned long find_symbol(unsigned long base, const char *sym)
{
    ElfW(Ehdr) *eh = (ElfW(Ehdr) *)base;
    ElfW(Shdr) *sh = (ElfW(Shdr) *)(base + eh->e_shoff);
    ElfW(Sym) *syms = 0;
    const char *strs = 0;
    int nsyms = 0;

    for (int i = 0; i < eh->e_shnum; i++) {
        if (sh[i].sh_type == SHT_DYNSYM) {
            syms = (ElfW(Sym) *)(base + sh[i].sh_offset);
            nsyms = (int)(sh[i].sh_size / sizeof(ElfW(Sym)));
            strs = (const char *)(base + sh[sh[i].sh_link].sh_offset);
        }
    }
    if (!syms) return 0;
    for (int i = 0; i < nsyms; i++) {
        if (syms[i].st_value && strs &&
            strcmp(strs + syms[i].st_name, sym) == 0)
            return base + syms[i].st_value;
    }
    return 0;
}

/* 16 字节 ARM64 detour: ldr x16, [pc+8]; br x16; .quad stub */
static void install_detour(unsigned long fn, unsigned long stub)
{
    unsigned char code[16];
    /* ldr x16, #8 */
    code[0]=0x50; code[1]=0x00; code[2]=0x00; code[3]=0x58;
    /* br x16 */
    code[4]=0x00; code[5]=0x02; code[6]=0x1f; code[7]=0xd6;
    memcpy(code + 8, &stub, 8);
    mem_poke(fn, code, sizeof(code));
}

static int patch_module(struct dl_phdr_info *info)
{
    unsigned long base = info->dlpi_addr;
    int patched = 0;

    for (size_t t = 0; t < sizeof(TARGETS) / sizeof(TARGETS[0]); t++) {
        unsigned long fn = find_symbol(base, TARGETS[t]);
        if (fn) {
            unsigned long stub = (unsigned long)stub_out_x0;
            install_detour(fn, stub);
            patched++;
            lg("patched %s", TARGETS[t]);
        }
    }
    return patched;
}

static int phdr_cb(struct dl_phdr_info *info, size_t size, void *data)
{
    (void)size; (void)data;
    const char *nm = info->dlpi_name ? info->dlpi_name : "";
    if (!strstr(nm, "libwvhidl.so") && !strstr(nm, "libcrypto.so"))
        return 0;
    lg("scanning %s", nm);
    return patch_module(info);
}

/* 部分目标符号不在导出表时, 退化为按 /proc/self/maps 的 ELF 头解析 —
 * primary libwvhidl, fallback libcrypto */
__attribute__((constructor))
static void wvhidl_hook_init(void)
{
    char prop[PROP_VALUE_MAX];

    if (__system_property_get(PROP_ID, fake_id) <= 0) {
        lg("no spoof id prop yet, idle");
        return;                              /* service.sh 会先 setprop */
    }

    /* string::assign 符号 (libc++): 通过 dlsym RTLD_DEFAULT 解析 */
    str_assign = (string_assign_t)dlsym(RTLD_DEFAULT,
        "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS9_9allocatorIcEEE6assignEPKc");
    if (!str_assign) {
        lg("no hookable seam (no libc++ assign)");
        return;
    }

    dl_iterate_phdr(phdr_cb, 0);
    lg("init done");
}
