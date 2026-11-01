/*
 * inject.c — ptrace 远程 dlopen 注入器 (arm64 Android)
 * 重建自原模块 DRMID-inject 的行为: inject <pid> <so-path>
 *
 * 核心技巧 (标准 syscall 劫持):
 *   1. PTRACE_SEIZE + PTRACE_INTERRUPT 强停目标线程
 *      (对阻塞在 binder ioctl / epoll 的线程同样有效)
 *   2. GETREGSET 保存现场; 此时该线程有一个"挂起的阻塞 syscall"
 *   3. process_vm_writev 把 .so 路径写到线程栈下方 (sp-0x800)
 *   4. 恢复时: x0=路径地址, x1=RTLD_NOW, pc=远程 dlopen, lr=原 pc;
 *      NT_ARM_SYSTEM_CALL 把挂起的 syscall 改号为 sched_yield,
 *      使内核的 syscall 重启机制不会把线程拉回阻塞调用
 *   5. dlopen 返回到原 pc, 线程回到自己的循环; 注入库构造函数完成钩子安装
 *
 * 注: 挂起的 ioctl 会被本次注入消耗, HAL 的 binder 线程池可自行恢复。
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
#include <sys/user.h>
#include <linux/elf.h>

#ifndef NT_ARM_SYSTEM_CALL
#define NT_ARM_SYSTEM_CALL 0x404
#endif

#define MAPS_LINE_LEN 512

static void remote_poke(pid_t pid, unsigned long addr,
                        const void *buf, size_t len)
{
    struct iovec local = { (void *)buf, len };
    struct iovec remote = { (void *)addr, len };
    process_vm_writev(pid, &local, 1, &remote, 1, 0);
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

/* 在远程 linker64 里找一条现成的 svc #0 (0xd4000001), 备用于 syscall 步进 */
static unsigned long find_svc(pid_t pid)
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

static void set_regs_and_syscall(pid_t tid, struct user_pt_regs *regs, long nr)
{
    struct iovec iov = { regs, sizeof(*regs) };
    ptrace(PTRACE_SETREGSET, tid, (void *)NT_PRSTATUS, iov);
    if (nr >= 0) {
        long call = nr;
        struct iovec siov = { &call, sizeof(call) };
        ptrace(PTRACE_SETREGSET, tid, (void *)NT_ARM_SYSTEM_CALL, &siov);
    }
}

int main(int argc, char **argv)
{
    pid_t pid, tid;
    const char *sopath;
    unsigned long local_dl, local_base, remote_base, remote_dlopen, svc_addr;
    unsigned long path_addr;
    struct user_pt_regs regs, saved;
    struct iovec iov = { &regs, sizeof(regs) };
    char pathbuf[256], taskdir[64];
    struct iovec local, remote;
    int status, w;

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
    svc_addr = find_svc(pid);

    /* 选一个线程并 SEIZE + INTERRUPT (阻塞中的线程同样会被强停) */
    snprintf(taskdir, sizeof(taskdir), "/proc/%d/task", pid);
    {
        FILE *f = fopen(taskdir, "r");
        char tbuf[64];
        tid = 0;
        if (!f) { perror("task dir"); return 1; }
        while (fgets(tbuf, sizeof(tbuf), f)) {
            tid = (pid_t)atoi(tbuf);
            if (tid > 0) break;
        }
        fclose(f);
    }
    if (!tid) { perror("no tid"); return 1; }

    printf("target tid %d\n", tid);
    if (ptrace(PTRACE_SEIZE, tid, 0, 0) < 0) { perror("PTRACE_SEIZE"); return 1; }
    ptrace(PTRACE_INTERRUPT, tid, 0, 0);
    waitpid(tid, &status, 0);
    ptrace(PTRACE_GETREGSET, tid, (void *)NT_PRSTATUS, iov);
    saved = regs;
    printf("interrupted: pc=%llx sp=%llx\n",
           (unsigned long long)regs.pc, (unsigned long long)regs.sp);

    /* .so 路径写到线程栈下方 (避开 red zone) */
    path_addr = (saved.sp - 0x800) & ~0xfUL;
    local.iov_base  = (void *)sopath;
    local.iov_len   = strlen(sopath) + 1;
    remote.iov_base = (void *)path_addr;
    remote.iov_len  = strlen(sopath) + 1;
    if (process_vm_writev(pid, &local, 1, &remote, 1, 0) < 0) {
        perror("process_vm_writev");
        ptrace(PTRACE_DETACH, tid, 0, 0);
        return 1;
    }

    /* 调用 dlopen(path, RTLD_NOW=2):
     * pc = 远程 dlopen, lr = 原 pc (dlopen 返回后线程回到自己的循环),
     * NT_ARM_SYSTEM_CALL 把挂起的阻塞 syscall 改号为 sched_yield,
     * 避免 syscall 重启机制把线程拉回阻塞调用 */
    regs = saved;
    regs.regs[0] = path_addr;
    regs.regs[1] = 2;                        /* RTLD_NOW */
    regs.regs[30] = saved.pc;                /* lr = 原返回点 */
    regs.pc = remote_dlopen;
    set_regs_and_syscall(tid, &regs, 124 /* sched_yield */);

    ptrace(PTRACE_CONT, tid, 0, 0);

    /* 轮询 maps 确认钩子已装 (最多 10 秒) */
    {
        char maps[64], line[512];
        int found = 0;
        snprintf(maps, sizeof(maps), "/proc/%d/maps", pid);
        for (w = 0; w < 20 && !found; w++) {
            usleep(500 * 1000);
            FILE *f = fopen(maps, "r");
            if (!f) break;
            while (fgets(line, sizeof(line), f)) {
                if (strstr(line, "DRMID_")) { found = 1; break; }
            }
            fclose(f);
        }
        printf("hook %s after %d ms\n", found ? "DETECTED" : "not seen", w * 500);
    }

    /* 恢复 seized 线程的寄存器现场并分离 */
    regs = saved;
    ptrace(PTRACE_SETREGSET, tid, (void *)NT_PRSTATUS, iov);
    ptrace(PTRACE_DETACH, tid, 0, 0);
    return 0;
}
