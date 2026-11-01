/*
 * inject.c — ptrace 远程 dlopen 注入器 (arm64 Android)
 * TencDRM 远程 dlopen 注入器。
 *
 * 原版手法:
 *   1. sym_off() 解析磁盘上的 libdl.so ELF, 取 dlopen/dlclose 的 st_value
 *   2. /proc/<pid>/maps 找 libdl.so 基址 → 远程 dlopen/dlclose 地址
 *   3. PTRACE_ATTACH → POKETEXT 在 dlclose 入口写入 BRK #0 (陷阱)
 *   4. .so 路径写入 (sp&~0xf)-512
 *   5. 寄存器: x0=路径, x1=RTLD_NOW, pc=远程 dlopen, lr=dlclose(陷阱)
 *   6. CONT → dlopen 执行完返回时撞上 BRK → SIGTRAP → x0 即句柄
 *   7. 恢复 dlclose 原指令与寄存器 → PTRACE_DETACH
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/user.h>

#define MAPS_LINE_LEN 512

/* 解析 ELF 文件, 返回符号在模块内的偏移 (st_value); 失败返回 0 */
static unsigned long sym_off(const char *path, const char *sym)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    off_t sz = lseek(fd, 0, SEEK_END);
    if (sz <= 0) { close(fd); return 0; }
    lseek(fd, 0, SEEK_SET);
    unsigned char *map = mmap(0, sz, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (map == (unsigned char *)-1) return 0;

    unsigned long result = 0;
    Elf64_Ehdr *eh = (Elf64_Ehdr *)map;
    int shnum = eh->e_shnum;
    if (shnum) {
        Elf64_Shdr *sh = (Elf64_Shdr *)(map + eh->e_shoff);
        unsigned char *symtab = 0, *strtab = 0;
        size_t count = 0;
        for (int i = 0; i < shnum; i++) {
            if (sh[i].sh_type == SHT_DYNSYM) {
                symtab = map + sh[i].sh_offset;
                count  = sh[i].sh_size / sizeof(Elf64_Sym);
                strtab = map + sh[sh[i].sh_link].sh_offset;
            }
        }
        if (count && strtab) {
            Elf64_Sym *s = (Elf64_Sym *)symtab;
            for (size_t i = 0; i < count; i++) {
                if (s[i].st_name && !strcmp(strtab + s[i].st_name, sym)) {
                    result = s[i].st_value;
                    break;
                }
            }
        }
    }
    munmap(map, sz);
    return result;
}

int main(int argc, char **argv)
{
    if (argc <= 2) {
        printf("usage: inject <pid> <so>\n");
        return 2;
    }
    int pid = atoi(argv[1]);
    const char *sopath = argv[2];

    /* dlopen/dlclose 偏移: 优先 APEX 路径, 回退 /system/lib64 */
    const char *libdl_path = "/apex/com.android.runtime/lib64/bionic/libdl.so";
    unsigned long off_dlopen = sym_off(libdl_path, "dlopen");
    int need_maps = 0;
    if (!off_dlopen) {
        libdl_path = "/system/lib64/libdl.so";
        off_dlopen = sym_off(libdl_path, "dlopen");
        if (!off_dlopen) need_maps = 1;
    }

    /* /proc/<pid>/maps 找 libdl.so 基址 (第一行匹配) */
    unsigned long base = 0;
    char maps[64], line[MAPS_LINE_LEN];
    snprintf(maps, sizeof(maps), "/proc/%d/maps", pid);
    FILE *f = fopen(maps, "r");
    if (f) {
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "libdl.so") && sscanf(line, "%lx", &base) == 1)
                break;
        }
        fclose(f);
    } else {
        need_maps = 1;
    }
    if ((need_maps & 1) || !base || !off_dlopen) {
        printf("resolve fail b=%lx o=%lx\n", base, off_dlopen);
        return 1;
    }

    unsigned long off_dlclose = sym_off(libdl_path, "dlclose");
    if (!base || !off_dlopen || !off_dlclose) {
        printf("resolve fail b=%lx o=%lx cl=%lx\n", base, off_dlopen, off_dlclose);
        return 1;
    }

    unsigned long remote_dlopen  = base + off_dlopen;
    unsigned long remote_dlclose = base + off_dlclose;
    printf("dlopen=%lx ra=%lx\n", remote_dlopen, remote_dlclose);

    if (ptrace(PTRACE_ATTACH, pid, 0, 0) < 0) {
        perror("attach");
        return 1;
    }
    int status;
    waitpid(pid, &status, 0);

    struct user_pt_regs regs;                /* 272 字节, 与原版 GETREGSET 一致 */
    struct iovec iov = { &regs, sizeof(regs) };
    iov.iov_len = 272;
    if (ptrace(PTRACE_GETREGSET, pid, (void *)1 /*NT_PRSTATUS*/, &iov) & 0x80000000) {
        perror("getregs");
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return 1;
    }
    struct user_pt_regs orig = regs;

    /* dlclose 入口写入 BRK #0 (保留原值高 32 位以防万一) */
    unsigned long orig_word = ptrace(PTRACE_PEEKTEXT, pid, remote_dlclose, 0);
    ptrace(PTRACE_POKETEXT, pid, remote_dlclose,
           (orig_word & 0xFFFFFFFF00000000ULL) | 0xD4200000ULL);

    /* .so 路径写到栈下对齐区 */
    unsigned long sp_aligned = regs.sp & ~0xfUL;
    unsigned long path_addr  = sp_aligned - 512;
    struct iovec lvec = { (void *)sopath, strlen(sopath) + 1 };
    struct iovec rvec = { (void *)path_addr, strlen(sopath) + 1 };
    process_vm_writev(pid, &lvec, 1, &rvec, 1, 0);

    /* 寄存器: x0=路径, x1=RTLD_NOW, sp=栈区-768, pc=dlopen, lr=dlclose(陷阱) */
    memset(&regs, 0, sizeof(regs));
    regs.regs[0] = path_addr;
    regs.regs[1] = 2;
    regs.sp = sp_aligned - 768;
    regs.regs[30] = remote_dlclose;
    regs.pc = remote_dlopen;
    ptrace(PTRACE_SETREGSET, pid, (void *)1, &iov);
    ptrace(PTRACE_CONT, pid, 0, 0);
    waitpid(pid, &status, 0);
    ptrace(PTRACE_GETREGSET, pid, (void *)1, &iov);

    int sig = (status & 0xff) == 127 ? (status >> 8) & 0xff : -1;
    printf("dlopen -> handle=%llx sig=%d pc=%llx\n",
           (unsigned long long)regs.regs[0], sig, (unsigned long long)regs.pc);

    /* 恢复 dlclose 原指令与原始寄存器 */
    ptrace(PTRACE_POKETEXT, pid, remote_dlclose, orig_word);
    iov.iov_base = &orig;
    ptrace(PTRACE_SETREGSET, pid, (void *)1, &iov);
    ptrace(PTRACE_DETACH, pid, 0, 0);
    return regs.regs[0] == 0;
}
