/*
 * inject.c — ptrace 远程 dlopen 注入器 (arm64 Android)
 * 重建自原模块 DRMID-inject 的行为: inject <pid> <so-path>
 *
 * 流程: PTRACE_SEIZE + PTRACE_INTERRUPT (可强停阻塞线程)
 *   → 解析 /proc/<pid>/maps 找 linker64 基址
 *   → 远程 dlopen/dlsym 地址 = 本地地址 - 本地基址 + 远程基址
 *   → 复用远程 linker 里现成的 svc 指令 (零代码植入) 执行远程 mmap
 *   → process_vm_writev 写入 .so 路径
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
#include <dirent.h>

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

/* 在远程 linker64 的可执行段里找一条现成的 svc #0 指令 (0xd4000001)。
 * 复用它执行远程系统调用, 避免向目标进程写入任何代码。 */
static unsigned long find_svc(pid_t pid, unsigned long mod_base)
{
    char path[64], line[MAPS_LINE_LEN];
    FILE *f;
    unsigned long start = 0, end = 0, addr;
    unsigned char *buf;
    size_t len;

    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    f = fopen(path, "r");
    if (!f) return 0;
    while (fgets(line, sizeof(line), f)) {
        char nm[MAPS_LINE_LEN];
        unsigned long s, e;
        char perms[8];
        nm[0] = '\0';
        if (sscanf(line, "%lx-%lx %7s %*s %*s %*s %255s", &s, &e, perms, nm) < 4)
            continue;
        if (strstr(nm, "linker64") && strstr(perms, "x")) {
            start = s; end = e;
        }
    }
    fclose(f);
    if (!start) return 0;

    len = end - start;
    buf = malloc(len);
    if (!buf) return 0;
    {
        struct iovec l = { buf, len }, r = { (void *)start, len };
        process_vm_readv(pid, &l, 1, &r, 1, 0);
    }
    for (addr = start; addr < start + len - 4; addr++) {
        size_t i = addr - start;
        if (buf[i] == 0x01 && buf[i+1] == 0x00 && buf[i+2] == 0x00 && buf[i+3] == 0xd4) {
            free(buf);
            return addr;
        }
    }
    free(buf);
    return 0;
}

/*
 * 复用远程 svc 指令执行一次系统调用:
 *   x8=nr, x0..x5=参数, pc=svc 指令, lr=陷阱页 (brk)
 * 系统调用返回后落入陷阱触发 SIGTRAP, 由 ptrace 捕获读回 x0。
 */
static long remote_syscall(pid_t pid, struct user_pt_regs *regs,
                           unsigned long svc_addr, long nr,
                           unsigned long a0, unsigned long a1,
                           unsigned long a2, unsigned long a3,
                           unsigned long a4, unsigned long a5,
                           unsigned long trap)
{
    struct iovec iov = { regs, sizeof(*regs) };
    int status;

    regs->regs[8] = (unsigned long)nr;
    regs->regs[0] = a0; regs->regs[1] = a1; regs->regs[2] = a2;
    regs->regs[3] = a3; regs->regs[4] = a4; regs->regs[5] = a5;
    regs->regs[30] = trap;                   /* lr = 陷阱 */
    regs->pc = svc_addr;
    ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, iov);
    ptrace(PTRACE_CONT, pid, 0, 0);
    waitpid(pid, &status, 0);                /* 停在陷阱 (SIGTRAP) */
    ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, iov);
    return (long)regs->regs[0];
}

int main(int argc, char **argv)
{
    pid_t pid, tid;
    const char *sopath;
    unsigned long local_dl, local_base, remote_base, remote_dlopen, svc_addr;
    unsigned long scratch, mmap_ret;
    struct user_pt_regs regs, saved;
    struct iovec iov = { &regs, sizeof(regs) };
    char pathbuf[256], taskdir[64];
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

    svc_addr = find_svc(pid, remote_base);
    if (!svc_addr) { perror("no svc insn in remote linker"); return 1; }

    /* PTRACE_SEIZE 不停线程; PTRACE_INTERRUPT 可强停阻塞中的线程 */
    snprintf(taskdir, sizeof(taskdir), "/proc/%d/task", pid);
    {
        DIR *d = opendir(taskdir);
        struct dirent *de;
        tid = 0;
        if (!d) { perror("task dir"); return 1; }
        while ((de = readdir(d)) != NULL) {
            int t = atoi(de->d_name);
            if (t > 0) { tid = (pid_t)t; break; }
        }
        closedir(d);
    }
    if (!tid) { perror("no tid"); return 1; }

    puts("M1:seize");
    if (ptrace(PTRACE_SEIZE, tid, 0, 0) < 0) { perror("PTRACE_SEIZE"); return 1; }
    puts("M2:interrupt");
    ptrace(PTRACE_INTERRUPT, tid, 0, 0);
    waitpid(tid, &status, 0);
    puts("M3:stopped");
    ptrace(PTRACE_GETREGSET, tid, (void *)NT_PRSTATUS, iov);
    saved = regs;

    /* 远程 mmap 一页 (复用 linker 的 svc 指令) */
    puts("M4:mmap-syscall");
    mmap_ret = remote_syscall(pid, &regs, svc_addr, 252 /*mmap*/, 0, 0x1000,
                              PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0, scratch);
    if (!mmap_ret || mmap_ret == (unsigned long)-1) {
        perror("remote mmap");
        ptrace(PTRACE_DETACH, tid, 0, 0);
        return 1;
    }
    fprintf(stderr, "M5:mmap-ok=%lu", mmap_ret);
    scratch = mmap_ret + 0x800;              /* 页内后半段作陷阱区 */

    /* 写入 .so 路径 */
    snprintf(pathbuf, sizeof(pathbuf), "%s", sopath);
    local.iov_base  = pathbuf;
    local.iov_len   = strlen(pathbuf) + 1;
    remote.iov_base = (void *)mmap_ret;
    remote.iov_len  = strlen(pathbuf) + 1;
    puts("M6:path-written");
    if (process_vm_writev(pid, &local, 1, &remote, 1, 0) < 0) {
        perror("process_vm_writev");
        ptrace(PTRACE_DETACH, tid, 0, 0);
        return 1;
    }

    /* 远程调用 dlopen(path, RTLD_NOW=2): lr 指向陷阱,
     * dlopen 返回即落入陷阱, 由 ptrace 捕获 */
    {
        unsigned char brk[4] = { 0x00, 0x00, 0x20, 0xd4 };
        unsigned char nop[4] = { 0x1f, 0x20, 0x03, 0xd5 };
        remote_poke(pid, scratch, brk, 4);
        regs = saved;
        regs.regs[0] = mmap_ret;
        regs.regs[1] = 2;                    /* RTLD_NOW */
        regs.regs[30] = scratch;             /* lr = 陷阱 */
        puts("M7:dlopen-call");
        regs.pc = remote_dlopen;
        ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, iov);
        ptrace(PTRACE_CONT, pid, 0, 0);
        waitpid(pid, &status, 0);            /* dlopen 返回 → 落入陷阱 */
        ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, iov);
        puts("M8:trap-hit");
        remote_poke(pid, scratch, nop, 4);   /* 陷阱位复原为 nop */
    }

    /* 恢复 seized 线程的寄存器现场并分离, 其阻塞调用原样继续 */
    regs = saved;
    ptrace(PTRACE_SETREGSET, tid, (void *)NT_PRSTATUS, iov);
    ptrace(PTRACE_DETACH, tid, 0, 0);
    return 0;
}
