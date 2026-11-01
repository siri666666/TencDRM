/*
 * inject.c — ptrace 远程 dlopen 注入器 (arm64 Android)
 * 重建自原模块 DRMID-inject 的行为: inject <pid> <so-path>
 *
 * 流程: PTRACE_ATTACH → 保存现场 → 解析 /proc/<pid>/maps 找 linker64 基址
 *   → 远程 dlopen/dlsym 地址 = 本地地址 - 本地基址 + 远程基址
 *   → 植入 svc+brk 断点 → 远程 mmap → process_vm_writev 写入 .so 路径
 *   → pc=远程 dlopen, lr=陷阱 → dlopen 执行完落入陷阱 → 恢复现场 → PTRACE_DETACH
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <linux/elf.h>

#define MAPS_LINE_LEN 512

static void remote_poke(pid_t pid, unsigned long addr,
                        const void *buf, size_t len)
{
    struct iovec local = { (void *)buf, len };
    struct iovec remote = { (void *)addr, len };
    process_vm_writev(pid, &local, 1, &remote, 1, 0);
}

static void remote_peek(pid_t pid, unsigned long addr,
                        void *buf, size_t len)
{
    struct iovec local = { buf, len };
    struct iovec remote = { (void *)addr, len };
    process_vm_readv(pid, &local, 1, &remote, 1, 0);
}

static unsigned long find_module_base(pid_t pid, const char *mod)
{
    char path[64], line[MAPS_LINE_LEN];
    FILE *f;
    unsigned long best = 0;

    if (pid > 0)
        snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    else
        snprintf(path, sizeof(path), "/proc/self/maps");

    f = fopen(path, "r");
    if (!f) return 0;
    while (fgets(line, sizeof(line), f)) {
        unsigned long start, end;
        char perms[8], nm[MAPS_LINE_LEN];
        nm[0] = '\0';
        if (sscanf(line, "%lx-%lx %7s %*s %*s %*s %255s", &start, &end,
                   perms, nm) < 4)
            continue;
        if (strstr(nm, mod) && start > best && (start & 0xfff) == 0)
            best = start;
    }
    fclose(f);
    return best;
}

/*
 * 在 tracee 当前 pc 处植入 svc+brk, 执行一次系统调用后停在 brk,
 * 读取返回值, 恢复原指令与寄存器。
 */
static long remote_syscall(pid_t pid, struct user_pt_regs *regs, long nr,
                           unsigned long a0, unsigned long a1,
                           unsigned long a2, unsigned long a3,
                           unsigned long a4, unsigned long a5)
{
    unsigned long pc = regs->pc;
    unsigned char orig[8], trap[8];
    struct iovec iov = { regs, sizeof(*regs) };
    int status;
    long ret;

    trap[0] = 0x01; trap[1] = 0x00; trap[2] = 0x00; trap[3] = 0xd4;   /* svc #0 */
    trap[4] = 0x00; trap[5] = 0x00; trap[6] = 0x20; trap[7] = 0xd4;   /* brk #0 */
    remote_peek(pid, pc, orig, 8);
    remote_poke(pid, pc, trap, 8);

    regs->regs[8] = (unsigned long)nr;
    regs->regs[0] = a0; regs->regs[1] = a1; regs->regs[2] = a2;
    regs->regs[3] = a3; regs->regs[4] = a4; regs->regs[5] = a5;
    regs->pstate &= ~(unsigned long)0x20;
    ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, iov);
    ptrace(PTRACE_CONT, pid, 0, 0);
    waitpid(pid, &status, 0);                 /* 停在 brk (SIGTRAP) */
    ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, iov);
    ret = (long)regs->regs[0];

    remote_poke(pid, pc, orig, 8);            /* 恢复原指令 */
    regs->pc = pc;                            /* 复位到原指令 */
    return ret;
}

int main(int argc, char **argv)
{
    pid_t pid;
    const char *sopath;
    unsigned long local_dl, local_base, remote_base, remote_dlopen;
    unsigned long scratch;
    struct user_pt_regs regs, saved;
    struct iovec iov = { &regs, sizeof(regs) };
    unsigned long mmap_ret;
    char pathbuf[256];
    struct iovec local, remote;
    int status;

    if (argc != 3) {
        printf("usage: inject <pid> <so>\n");
        return 1;
    }
    pid    = (pid_t)atoi(argv[1]);
    sopath = argv[2];

    local_dl = (unsigned long)dlsym(RTLD_DEFAULT, "dlopen");
    if (!local_dl) { perror("dlsym dlopen"); return 1; }
    local_base = find_module_base(0, "linker64");
    if (!local_base) local_base = find_module_base(0, "libdl.so");
    if (!local_base) { perror("local base"); return 1; }

    remote_base = find_module_base(pid, "linker64");
    if (!remote_base) remote_base = find_module_base(pid, "libdl.so");
    if (!remote_base) { perror("remote base"); return 1; }

    remote_dlopen = local_dl - local_base + remote_base;

    if (ptrace(PTRACE_ATTACH, pid, 0, 0) < 0) { perror("PTRACE_ATTACH"); return 1; }
    waitpid(pid, &status, 0);
    ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, iov);
    saved = regs;

    /* 远程匿名 mmap 一页 (svc 断点法) */
    mmap_ret = remote_syscall(pid, &regs, 252 /*mmap*/, 0, 0x1000,
                              PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (!mmap_ret || mmap_ret == (unsigned long)-1) {
        perror("remote mmap");
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return 1;
    }
    scratch = mmap_ret + 0x800;               /* 页内后半段作陷阱区 */

    /* 写入 .so 路径 */
    snprintf(pathbuf, sizeof(pathbuf), "%s", sopath);
    local.iov_base  = pathbuf;
    local.iov_len   = strlen(pathbuf) + 1;
    remote.iov_base = (void *)mmap_ret;
    remote.iov_len  = strlen(pathbuf) + 1;
    if (process_vm_writev(pid, &local, 1, &remote, 1, 0) < 0) {
        perror("process_vm_writev");
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return 1;
    }

    /* 远程调用 dlopen(path, RTLD_NOW=2): lr 指向 brk 陷阱,
     * dlopen 返回即落入陷阱, 由 ptrace 捕获 */
    {
        unsigned char brk[4] = { 0x00, 0x00, 0x20, 0xd4 };
        unsigned char nop[4] = { 0x1f, 0x20, 0x03, 0xd5 };
        remote_poke(pid, scratch, brk, 4);
        regs = saved;
        regs.regs[0] = mmap_ret;
        regs.regs[1] = 2;                     /* RTLD_NOW */
        regs.regs[30] = scratch;              /* lr = 陷阱 */
        regs.pc = remote_dlopen;
        ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, iov);
        ptrace(PTRACE_CONT, pid, 0, 0);
        waitpid(pid, &status, 0);             /* dlopen 返回 → 落入陷阱 */
        ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, iov);
        remote_poke(pid, scratch, nop, 4);    /* 陷阱位复原为 nop */
    }

    /* 恢复附着时的寄存器现场并分离, tracee 从原指令继续 */
    regs = saved;
    ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, iov);
    ptrace(PTRACE_DETACH, pid, 0, 0);
    return 0;
}
