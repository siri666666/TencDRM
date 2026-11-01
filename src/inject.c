/*
 * inject.c — minimal ptrace remote-dlopen injector (arm64 Android)
 * 重建自原模块 DRMID-inject 的行为: inject <pid> <so-path>
 *
 * 流程: PTRACE_ATTACH → 解析 /proc/<pid>/maps 找 linker64 基址
 *   → 远程 dlopen/dlsym 地址 = 本地地址 - 本地基址 + 远程基址
 *   → 远程 mmap 一页 → process_vm_writev 写入 .so 路径
 *   → 远程调用 dlopen(path, RTLD_NOW) → PTRACE_DETACH
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
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <linux/elf.h>

#define MAPS_LINE_LEN 512

/* 从 /proc/<pid>/maps 找到包含 addr 的模块基址; 本地模式找 own libdl 基址 */
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
        char perms[8], name[MAPS_LINE_LEN];
        name[0] = '\0';
        if (sscanf(line, "%lx-%lx %7s %*s %*s %*s %255s", &start, &end,
                   perms, name) < 4)
            continue;
        if (strstr(name, mod) && start > best && (start & 0xfff) == 0)
            best = start;
    }
    fclose(f);
    return best;
}

/* ptrace 远程系统调用: 设置 x8=nr 并执行, 返回 x0 */
static long remote_syscall(pid_t pid, struct user_pt_regs *regs, long nr,
                           unsigned long a0, unsigned long a1,
                           unsigned long a2, unsigned long a3,
                           unsigned long a4, unsigned long a5)
{
    struct user_pt_regs r = *regs, out;
    struct iovec iov = { &r, sizeof(r) };

    r.regs[8] = (unsigned long)nr;          /* x8 = syscall nr */
    r.regs[0] = a0; r.regs[1] = a1; r.regs[2] = a2;
    r.regs[3] = a3; r.regs[4] = a4; r.regs[5] = a5;
    r.pc += 4;                              /* 跳过当前指令, svc 位于其后 */
    ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &iov);
    ptrace(PTRACE_CONT, pid, 0, 0);
    waitpid(pid, 0, 0);
    ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov);
    *regs = r;                              /* 回写当前寄存器状态 */
    return r.regs[0];
}

int main(int argc, char **argv)
{
    pid_t pid;
    const char *sopath;
    unsigned long local_dl, local_base, remote_base, remote_dlopen;
    struct user_pt_regs regs, orig;
    struct iovec iov = { &regs, sizeof(regs) };
    long mmap_ret;
    unsigned long remote_buf;
    char pathbuf[256];
    struct iovec local, remote;
    int status;

    if (argc != 3) {
        printf("usage: inject <pid> <so>\n");
        return 1;
    }
    pid    = (pid_t)atoi(argv[1]);
    sopath = argv[2];

    /* 本地: dlopen 地址与所在模块基址 (libdl.so / linker64) */
    local_dl = (unsigned long)dlsym(RTLD_DEFAULT, "dlopen");
    if (!local_dl) { perror("dlsym dlopen"); return 1; }
    local_base = find_module_base(0, "linker64");
    if (!local_base) local_base = find_module_base(0, "libdl.so");
    if (!local_base) { perror("local base"); return 1; }

    /* 远程: 同名模块基址 */
    remote_base = find_module_base(pid, "linker64");
    if (!remote_base) remote_base = find_module_base(pid, "libdl.so");
    if (!remote_base) { perror("remote base"); return 1; }

    remote_dlopen = local_dl - local_base + remote_base;

    if (ptrace(PTRACE_ATTACH, pid, 0, 0) < 0) { perror("PTRACE_ATTACH"); return 1; }
    waitpid(pid, &status, 0);
    ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov);
    orig = regs;

    /* 远程匿名 mmap 一页 */
    mmap_ret = remote_syscall(pid, &regs, 252 /*mmap*/, 0, 0x1000,
                              PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if ((long)mmap_ret <= 0 && mmap_ret != -1) { /* mmap 返回地址或错误 */ }
    remote_buf = (unsigned long)mmap_ret;
    if (!remote_buf) { perror("remote mmap"); goto out; }

    /* 写入 .so 路径 */
    snprintf(pathbuf, sizeof(pathbuf), "%s", sopath);
    local.iov_base  = pathbuf;
    local.iov_len   = strlen(pathbuf) + 1;
    remote.iov_base = (void *)remote_buf;
    remote.iov_len  = strlen(pathbuf) + 1;
    if (process_vm_writev(pid, &local, 1, &remote, 1, 0) < 0) {
        perror("process_vm_writev");
        goto out;
    }

    /* 远程调用 dlopen(path, RTLD_NOW=2) */
    remote_syscall(pid, &regs, 0, 0, 0, 0, 0, 0, 0);  /* 占位 */
    {
        /* 直接以函数调用方式: 恢复原始寄存器后设置 pc=remote_dlopen */
        struct user_pt_regs c = orig;
        struct iovec cv = { &c, sizeof(c) };
        c.regs[0] = remote_buf;
        c.regs[1] = 2;                       /* RTLD_NOW */
        c.pc = remote_dlopen;
        ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &cv);
        ptrace(PTRACE_CONT, pid, 0, 0);
        waitpid(pid, &status, 0);
        ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &cv);
    }

out:
    ptrace(PTRACE_DETACH, pid, 0, 0);
    return 0;
}
