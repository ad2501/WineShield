
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

static const int wine_allowed_syscalls[] = {
    __NR_read,
    __NR_write,
    __NR_open,
    __NR_close,
    __NR_mmap,
    __NR_mprotect,
    __NR_munmap,
    __NR_brk,
    __NR_rt_sigaction,
    __NR_rt_sigprocmask,
    __NR_ioctl,
    __NR_access,
    __NR_getpid,
    __NR_clone,
    __NR_exit,
    __NR_exit_group,
    -1
};

static void build_filter(
    struct sock_fprog *prog,
    const int *allowed
) {
    int count = 0;
    while (allowed[count] != -1) count++;

    int total = count * 2 + 2;

    struct sock_filter *filter =
        malloc(sizeof(struct sock_filter) * total);

    int i = 0;

    filter[i++] = (struct sock_filter)
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
            offsetof(struct seccomp_data, nr));

    for (int j = 0; j < count; j++) {
        filter[i++] = (struct sock_filter)
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                allowed[j], 0, 1);

        filter[i++] = (struct sock_filter)
            BPF_STMT(BPF_RET | BPF_K,
                SECCOMP_RET_ALLOW);
    }

    filter[i++] = (struct sock_filter)
        BPF_STMT(BPF_RET | BPF_K,
            SECCOMP_RET_LOG);

    prog->len    = i;
    prog->filter = filter;
}

int wineshield_init_seccomp(int strict_mode) {
    struct sock_fprog prog = {0};

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        perror("prctl NO_NEW_PRIVS");
        return -1;
    }

    build_filter(&prog, wine_allowed_syscalls);

    if (syscall(SYS_seccomp,
                SECCOMP_SET_MODE_FILTER,
                0, &prog) < 0) {
        perror("seccomp");
        free(prog.filter);
        return -1;
    }

    free(prog.filter);
    printf("[WineShield] seccomp active\n");
    return 0;
}