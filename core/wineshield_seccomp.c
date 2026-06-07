/*
 * WineShield - seccomp-BPF Syscall Monitor
 * Kernel-level syscall filtering for Wine applications
 */

#include <seccomp.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

/* Initialize seccomp filter */
scmp_filter_ctx init_seccomp_filter(void) {
    scmp_filter_ctx ctx;
    
    /* Create filter with default ALLOW action */
    ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (ctx == NULL) {
        fprintf(stderr, "Error initializing seccomp filter\n");
        return NULL;
    }
    
    return ctx;
}

/* Add syscall to whitelist */
int add_syscall_to_filter(scmp_filter_ctx ctx, int syscall_num) {
    int rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, syscall_num, 0);
    if (rc < 0) {
        fprintf(stderr, "Error adding syscall %d\n", syscall_num);
        return -1;
    }
    return 0;
}

/* Block dangerous syscall */
int block_syscall(scmp_filter_ctx ctx, int syscall_num) {
    int rc = seccomp_rule_add(ctx, SCMP_ACT_KILL, syscall_num, 0);
    if (rc < 0) {
        fprintf(stderr, "Error blocking syscall %d\n", syscall_num);
        return -1;
    }
    return 0;
}

/* Load filter into kernel */
int load_seccomp_filter(scmp_filter_ctx ctx) {
    int rc = seccomp_load(ctx);
    if (rc < 0) {
        fprintf(stderr, "Error loading seccomp filter: %s\n", strerror(-rc));
        seccomp_release(ctx);
        return -1;
    }
    return 0;
}

int main(int argc, char *argv[]) {
    scmp_filter_ctx ctx;
    
    ctx = init_seccomp_filter();
    if (ctx == NULL) {
        return 1;
    }
    
    if (load_seccomp_filter(ctx) != 0) {
        return 1;
    }
    
    seccomp_release(ctx);
    return 0;
}
