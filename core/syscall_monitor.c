/*
 * syscall_monitor.c — WineShield seccomp-BPF syscall filter
 *
 * Multi-layer Linux security framework for Wine.  Provides three
 * operational modes: MONITOR (log all), BALANCED (block dangerous),
 * and STRICT (only allow whitelist).
 *
 * Compile:  gcc -Wall -Wextra -pedantic -std=c99 -D_GNU_SOURCE \
 *               -DTEST_STANDALONE -o syscall_monitor syscall_monitor.c
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/elf-em.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>

/* ------------------------------------------------------------------ */
/*  Mode definitions                                                   */
/* ------------------------------------------------------------------ */
#define MODE_MONITOR   0   /* default = SECCOMP_RET_LOG, log all      */
#define MODE_BALANCED  1   /* default = SECCOMP_RET_ALLOW, block bad  */
#define MODE_STRICT    2   /* default = SECCOMP_RET_KILL_PROCESS      */

/* ------------------------------------------------------------------ */
/*  Whitelist for STRICT mode  (~120 syscalls organized by category)  */
/* ------------------------------------------------------------------ */
static const int strict_whitelist[] = {
    /* ---- Process ---- */
    __NR_clone,
    __NR_fork,
    __NR_vfork,
    __NR_exit,
    __NR_exit_group,
    __NR_getpid,
    __NR_gettid,
    __NR_getppid,
    __NR_getpgrp,
    __NR_setsid,
    __NR_setpgid,
    __NR_wait4,
    __NR_waitid,
    __NR_execve,
    __NR_umask,
    __NR_prctl,
    __NR_arch_prctl,

    /* ---- Memory ---- */
    __NR_mmap,
    __NR_munmap,
    __NR_mprotect,
    __NR_brk,
    __NR_mremap,
    __NR_msync,
    __NR_madvise,
    __NR_mincore,
    __NR_mlock,
    __NR_munlock,
    __NR_mlockall,
    __NR_munlockall,
    __NR_mbind,
#if defined(__NR_set_mempolicy)
    __NR_set_mempolicy,
#endif
#if defined(__NR_get_mempolicy)
    __NR_get_mempolicy,
#endif
    __NR_shmget,
    __NR_shmat,
    __NR_shmdt,
    __NR_shmctl,

    /* ---- File I/O ---- */
    __NR_read,
    __NR_write,
    __NR_pread64,
    __NR_pwrite64,
    __NR_readv,
    __NR_writev,
    __NR_preadv,
    __NR_pwritev,
    __NR_open,
    __NR_openat,
    __NR_creat,
    __NR_close,
    __NR_lseek,
    __NR_ftruncate,
    __NR_truncate,
    __NR_ioctl,
#if defined(__NR_fallocate)
    __NR_fallocate,
#endif
    __NR_fstat,
    __NR_stat,
    __NR_lstat,
    __NR_newfstatat,
    __NR_readlink,
    __NR_readlinkat,
    __NR_getdents,
    __NR_getdents64,
    __NR_fcntl,
    __NR_flock,
    __NR_dup,
    __NR_dup2,
    __NR_dup3,
    __NR_pipe,
    __NR_pipe2,
    __NR_splice,
    __NR_tee,
    __NR_sendfile,
    __NR_copy_file_range,
    __NR_access,
    __NR_faccessat,
#if defined(__NR_faccessat2)
    __NR_faccessat2,
#endif
    __NR_statx,

    /* ---- Signal ---- */
    __NR_rt_sigaction,
    __NR_rt_sigprocmask,
    __NR_rt_sigreturn,
    __NR_rt_sigtimedwait,
    __NR_rt_sigpending,
    __NR_rt_sigsuspend,
    __NR_rt_sigqueueinfo,
    __NR_kill,
    __NR_tgkill,
    __NR_sigaltstack,
    __NR_signalfd,
    __NR_signalfd4,

    /* ---- Time ---- */
    __NR_clock_gettime,
    __NR_clock_getres,
    __NR_nanosleep,
    __NR_gettimeofday,
    __NR_settimeofday,
    __NR_time,
    __NR_timerfd_create,
    __NR_timerfd_settime,
    __NR_timerfd_gettime,

    /* ---- Network ---- */
    __NR_socket,
    __NR_connect,
    __NR_bind,
    __NR_listen,
    __NR_accept,
    __NR_accept4,
    __NR_sendto,
    __NR_sendmsg,
    __NR_sendmmsg,
    __NR_recvfrom,
    __NR_recvmsg,
    __NR_recvmmsg,
    __NR_getsockname,
    __NR_getpeername,
    __NR_getsockopt,
    __NR_setsockopt,
    __NR_shutdown,
    __NR_socketpair,

    /* ---- Filesystem ---- */
    __NR_mkdir,
    __NR_mkdirat,
    __NR_rmdir,
    __NR_unlink,
    __NR_unlinkat,
    __NR_rename,
    __NR_renameat,
#if defined(__NR_renameat2)
    __NR_renameat2,
#endif
    __NR_symlink,
    __NR_symlinkat,
    __NR_link,
    __NR_linkat,
    __NR_chdir,
    __NR_fchdir,
    __NR_getcwd,
    __NR_chmod,
    __NR_fchmod,
    __NR_chown,
    __NR_fchown,
    __NR_lchown,
    __NR_statfs,
    __NR_fstatfs,
    __NR_utimensat,
    __NR_utime,
    __NR_utimes,
    __NR_listxattr,
    __NR_getxattr,
    __NR_setxattr,
    __NR_lgetxattr,
    __NR_lsetxattr,
    __NR_fgetxattr,
    __NR_fsetxattr,
    __NR_removexattr,

    /* ---- System / Identity ---- */
    __NR_uname,
    __NR_sysinfo,
    __NR_getuid,
    __NR_geteuid,
    __NR_getgid,
    __NR_getegid,
    __NR_getresuid,
    __NR_getresgid,
    __NR_getgroups,
    __NR_getrlimit,
    __NR_setrlimit,
    __NR_getsid,
    __NR_getpriority,
    __NR_setpriority,
    __NR_getrusage,
    __NR_times,

    /* ---- Multiplexing / Event ---- */
    __NR_poll,
    __NR_ppoll,
    __NR_select,
    __NR_pselect6,
    __NR_epoll_create,
    __NR_epoll_create1,
    __NR_epoll_ctl,
    __NR_epoll_wait,
    __NR_epoll_pwait,
    __NR_eventfd,
    __NR_eventfd2,

    /* --- Async I/O ---- */
    __NR_io_setup,
    __NR_io_destroy,
    __NR_io_getevents,
    __NR_io_submit,
    __NR_io_cancel,

    /* ---- Misc ---- */
    __NR_getrandom,
    __NR_sched_yield,
    __NR_sched_getparam,
    __NR_sched_setparam,
    __NR_sched_getscheduler,
    __NR_sched_setscheduler,
    __NR_sched_getattr,
    __NR_sched_setattr,
    __NR_sched_get_priority_max,
    __NR_sched_get_priority_min,
    __NR_sched_rr_get_interval,
    __NR_sched_getaffinity,
    __NR_prlimit64,
    __NR_personality,
    __NR_futex,
    __NR_set_robust_list,
    __NR_get_robust_list,
    __NR_set_tid_address,
    __NR_restart_syscall,
    __NR_rseq,
    __NR_close_range,

    /* ---- timer ---- */
    __NR_timer_create,
    __NR_timer_settime,
    __NR_timer_gettime,
    __NR_timer_getoverrun,
    __NR_timer_delete,

    /* ---- inotify ---- */
    __NR_inotify_init,
    __NR_inotify_init1,
    __NR_inotify_add_watch,
    __NR_inotify_rm_watch,

    /* ---- memfd ---- */
#if defined(__NR_memfd_create)
    __NR_memfd_create,
#endif
#if defined(__NR_memfd_secret)
    __NR_memfd_secret,
#endif

    /* ---- landlock ---- */
#if defined(__NR_landlock_create_ruleset)
    __NR_landlock_create_ruleset,
#endif
#if defined(__NR_landlock_add_rule)
    __NR_landlock_add_rule,
#endif
#if defined(__NR_landlock_restrict_self)
    __NR_landlock_restrict_self,
#endif

    /* ---- userfaultfd ---- */
#if defined(__NR_userfaultfd)
    __NR_userfaultfd,
#endif

    /* ---- seccomp ---- */
#if defined(__NR_seccomp)
    __NR_seccomp,
#endif

    /* ---- sync family ---- */
    __NR_sync,
    __NR_fsync,
    __NR_fdatasync,
    __NR_syncfs,

    /* ---- Sentinel ---- */
    -1
};

/* ------------------------------------------------------------------ */
/*  Blacklist for BALANCED mode  (30+ dangerous syscalls)             */
/* ------------------------------------------------------------------ */
static const int balanced_blacklist[] = {
    __NR_ptrace,
    __NR_init_module,
    __NR_finit_module,
    __NR_delete_module,
    __NR_kexec_load,
#if defined(__NR_kexec_file_load)
    __NR_kexec_file_load,
#endif
    __NR_iopl,
    __NR_ioperm,
    __NR_bpf,
    __NR_perf_event_open,
    __NR_swapon,
    __NR_swapoff,
    __NR_syslog,
    __NR_sethostname,
    __NR_setdomainname,
    __NR_reboot,
    __NR_add_key,
    __NR_request_key,
    __NR_keyctl,
    __NR_process_vm_readv,
    __NR_process_vm_writev,
    __NR_vhangup,
    __NR_acct,
    __NR_adjtimex,
    __NR_clock_adjtime,
    __NR_clock_settime,
#if defined(__NR_nfsservctl)
    __NR_nfsservctl,
#endif
    __NR_get_kernel_syms,
    __NR_create_module,
    __NR_query_module,
    __NR_uselib,
    __NR_mknod,
    __NR_mknodat,
    __NR_name_to_handle_at,
    __NR_open_by_handle_at,
    __NR_fanotify_init,
    __NR_mount,
    __NR_umount2,
    __NR_pivot_root,
    __NR_chroot,
    __NR_sysfs,

    /* ---- Sentinel ---- */
    -1
};

/* ------------------------------------------------------------------ */
/*  Helper: count entries in a -1-terminated array                    */
/* ------------------------------------------------------------------ */
static int list_count(const int *list)
{
    int n = 0;
    while (list && list[n] != -1)
        n++;
    return n;
}

/* ------------------------------------------------------------------ */
/*  Build a seccomp-BPF filter program for the given mode.            */
/*  Returns 0 on success, -1 on error.                                */
/* ------------------------------------------------------------------ */
static int build_seccomp_filter(
    struct sock_fprog *prog,
    int                mode)
{
    const int  *syscall_list    = NULL;
    int         list_len        = 0;
    unsigned    default_action;
    unsigned    allow_action    = SECCOMP_RET_ALLOW;
    int         is_blacklist    = 0;

    switch (mode) {
    case MODE_MONITOR:
        default_action = SECCOMP_RET_LOG;
        break;
    case MODE_BALANCED:
        default_action = SECCOMP_RET_ALLOW;
        syscall_list   = balanced_blacklist;
        list_len       = list_count(balanced_blacklist);
        is_blacklist   = 1;
        break;
    case MODE_STRICT:
        default_action = SECCOMP_RET_KILL_PROCESS;
        syscall_list   = strict_whitelist;
        list_len       = list_count(strict_whitelist);
        is_blacklist   = 0;
        break;
    default:
        fprintf(stderr, "[WineShield] invalid seccomp mode: %d\n", mode);
        return -1;
    }

    /*
     * Program layout:
     *
     *  [0]  LD  arch
     *  [1]  JEQ AUDIT_ARCH_X86_64, jt=OFF_X86_64, jf=1
     *  [2]  JEQ AUDIT_ARCH_I386,   jt=1,          jf=1
     *  [3]  RET SECCOMP_RET_KILL_THREAD
     *  [4]  RET SECCOMP_RET_LOG                   (i386 handler)
     *  [5]  LD  nr                                (x86_64 handler start)
     *  [6+] syscall checks  (2 instructions per entry)
     *  [N]  RET <default_action>
     */
    const int arch_header_insns = 5; /* [0]..[4] */
    const int ld_nr_insns       = 1; /* [5] */
    const int pair_insns        = list_len * 2; /* JEQ + RET */
    const int default_insns     = 1; /* final RET */
    const int total_insns       = arch_header_insns +
                                  ld_nr_insns +
                                  pair_insns +
                                  default_insns;

    struct sock_filter *filter =
        malloc(sizeof(struct sock_filter) * (size_t)total_insns);
    if (!filter) {
        perror("[WineShield] malloc filter");
        return -1;
    }

    int ip = 0;

    /* ---- Architecture check ---- */
    filter[ip++] = (struct sock_filter)
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, arch));

    /*
     * Jump distances for the x86_64 check at [1]:
     *   jt = skip past [2],[3],[4]  → 3 instructions
     *   jf = skip  1 instruction    → [2] (i386 check)
     */
    filter[ip++] = (struct sock_filter)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                 AUDIT_ARCH_X86_64, 3, 1);

    filter[ip++] = (struct sock_filter)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                 AUDIT_ARCH_I386, 1, 1);

    /* Unknown architecture -> kill thread */
    filter[ip++] = (struct sock_filter)
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_THREAD);

    /* i386 / 32-bit: allow but log (Wine compatibility) */
    filter[ip++] = (struct sock_filter)
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_LOG);

    /*
     * ---- x86_64 syscall filter ----
     * [ip] = LD nr
     */
    filter[ip++] = (struct sock_filter)
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, nr));

    /* For each entry: JEQ + RET pair */
    for (int j = 0; j < list_len; j++) {
        int nr = syscall_list[j];

        if (is_blacklist) {
            /*
             * Blacklist (BALANCED mode):
             *   If nr matches -> skip 0 -> RET KILL_THREAD
             *   If nr doesn't match -> skip 1 -> skip the RET
             */
            filter[ip++] = (struct sock_filter)
                BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned)nr, 0, 1);
            filter[ip++] = (struct sock_filter)
                BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_THREAD);
        } else {
            /*
             * Whitelist (STRICT mode):
             *   If nr matches -> skip 0 -> RET ALLOW
             *   If nr doesn't match -> skip 1 -> skip the RET
             */
            filter[ip++] = (struct sock_filter)
                BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned)nr, 0, 1);
            filter[ip++] = (struct sock_filter)
                BPF_STMT(BPF_RET | BPF_K, allow_action);
        }
    }

    /* Default action */
    filter[ip++] = (struct sock_filter)
        BPF_STMT(BPF_RET | BPF_K, default_action);

    /* Sanity check */
    if (ip != total_insns) {
        fprintf(stderr,
                "[WineShield] BPF program size mismatch: "
                "expected %d, got %d\n", total_insns, ip);
        free(filter);
        return -1;
    }

    prog->len    = (unsigned short)ip;
    prog->filter = filter;
    return 0;
}

/* ------------------------------------------------------------------ */
/*  wineshield_init_seccomp — install the seccomp filter              */
/*                                                                     */
/*  Parameters:                                                        */
/*    mode: 0 = MONITOR, 1 = BALANCED, 2 = STRICT                     */
/*                                                                     */
/*  Returns: 0 on success, -1 on failure                               */
/* ------------------------------------------------------------------ */
int wineshield_init_seccomp(int mode)
{
    struct sock_fprog prog = { 0, NULL };
    int ret = -1;

    /* Build the BPF program */
    if (build_seccomp_filter(&prog, mode) != 0) {
        fprintf(stderr, "[WineShield] failed to build seccomp filter\n");
        return -1;
    }

    /* Grant new privileges so filter can be applied */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        perror("[WineShield] prctl NO_NEW_PRIVS");
        goto out;
    }

    /* Install the filter with TSYNC so it applies to all threads */
    if (syscall(SYS_seccomp,
                SECCOMP_SET_MODE_FILTER,
                SECCOMP_FILTER_FLAG_TSYNC,
                &prog) < 0) {
        perror("[WineShield] seccomp");
        goto out;
    }

    {
        const char *mode_name;
        switch (mode) {
        case MODE_MONITOR:  mode_name = "MONITOR";  break;
        case MODE_BALANCED: mode_name = "BALANCED"; break;
        case MODE_STRICT:   mode_name = "STRICT";   break;
        default:            mode_name = "UNKNOWN";  break;
        }
        printf("[WineShield] seccomp active (mode=%s)\n", mode_name);
    }

    ret = 0;

out:
    if (prog.filter) {
        free(prog.filter);
        prog.filter = NULL;
    }
    return ret;
}

/* ------------------------------------------------------------------ */
/*  Privilege dropping                                                 */
/* ------------------------------------------------------------------ */
static int drop_privileges(const char *username)
{
    if (!username) return 0;  /* no --user flag, skip */

    struct passwd *pw = getpwnam(username);
    if (!pw) {
        fprintf(stderr, "[WineShield] unknown user: %s\n", username);
        return -1;
    }

    /* Order: supplementary groups -> GID -> UID */
    if (initgroups(username, pw->pw_gid) != 0) {
        perror("[WineShield] initgroups");
        return -1;
    }
    if (setgid(pw->pw_gid) != 0) {
        perror("[WineShield] setgid");
        return -1;
    }
    if (setuid(pw->pw_uid) != 0) {
        perror("[WineShield] setuid");
        return -1;
    }

    /* Verify the drop succeeded */
    if (getuid() != pw->pw_uid || geteuid() != pw->pw_uid) {
        fprintf(stderr, "[WineShield] privilege drop verification FAILED: "
                "uid=%d, euid=%d, target=%d\n",
                getuid(), geteuid(), pw->pw_uid);
        return -1;
    }

    printf("[WineShield] dropped privileges to %s (uid=%d)\n",
           username, pw->pw_uid);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Local test / standalone entry point                                */
/* ------------------------------------------------------------------ */
#ifdef TEST_STANDALONE
static void usage(const char *argv0)
{
    fprintf(stderr,
            "Usage: %s --mode <monitor|balanced|strict> [--user <username>] [-- <cmd>...]\n"
            "\n"
            "Installs a seccomp filter in the given mode and runs\n"
            "the specified command (default: /bin/ls).\n"
            "\n"
            "Modes:\n"
            "  monitor   Log all syscalls, allow everything\n"
            "  balanced  Block dangerous syscalls, allow everything else\n"
            "  strict    Only allow whitelisted syscalls\n",
            argv0 ? argv0 : "syscall_monitor");
}

int main(int argc, char **argv)
{
    int mode = MODE_STRICT;   /* default mode */
    char *target_user = NULL;
    char *cmd    = NULL;
    int   cmd_i  = 0;

    /* Parse --mode argument */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
            i++;
            if (strcmp(argv[i], "monitor") == 0)
                mode = MODE_MONITOR;
            else if (strcmp(argv[i], "balanced") == 0)
                mode = MODE_BALANCED;
            else if (strcmp(argv[i], "strict") == 0)
                mode = MODE_STRICT;
            else {
                fprintf(stderr,
                        "Unknown mode: %s\n", argv[i]);
                usage(argv[0]);
                return -1;
            }
        } else if (strcmp(argv[i], "--user") == 0 && i + 1 < argc) {
            target_user = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0 ||
                   strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--") == 0) {
            cmd_i = i + 1;
            break;
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            usage(argv[0]);
            return -1;
        } else {
            /* First positional arg → start of command */
            cmd_i = i;
            break;
        }
    }

    /* Determine command to run */
    if (cmd_i > 0 && cmd_i < argc) {
        cmd = argv[cmd_i];
    } else {
        cmd = "/bin/ls";
    }

    /* Build argv for exec */
    int cmd_argc = 0;
    if (cmd_i > 0) {
        cmd_argc = argc - cmd_i;
    } else {
        /* default /bin/ls */
        cmd_argc = 1;
    }

    char **cmd_argv = malloc(sizeof(char *) * (size_t)(cmd_argc + 1));
    if (!cmd_argv) {
        perror("malloc");
        return -1;
    }

    if (cmd_i > 0) {
        for (int j = 0; j < cmd_argc; j++)
            cmd_argv[j] = argv[cmd_i + j];
    } else {
        cmd_argv[0] = "/bin/ls";
    }
    cmd_argv[cmd_argc] = NULL;

    /* Install the seccomp filter */
    if (wineshield_init_seccomp(mode) != 0) {
        fprintf(stderr,
                "[WineShield] failed to init seccomp (mode=%d)\n", mode);
        free(cmd_argv);
        return -1;
    }

    /* Drop privileges if --user was specified */
    if (drop_privileges(target_user) != 0) {
        fprintf(stderr, "[WineShield] privilege drop failed, aborting\n");
        free(cmd_argv);
        return -1;
    }

    /* Execute the test command */
    printf("[WineShield] executing: %s\n", cmd);
    fflush(stdout);

    execvp(cmd, cmd_argv);

    /* If exec fails */
    perror("[WineShield] execvp");
    free(cmd_argv);
    return -1;
}
#endif  /* TEST_STANDALONE */
