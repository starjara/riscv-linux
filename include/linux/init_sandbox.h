#include <linux/bpf.h>

#define IS_SANDBOX_ENABLED(type) ( \
                type == BPF_PROG_TYPE_SOCKET_FILTER \
                || type == BPF_PROG_TYPE_XDP \
                || type == BPF_PROG_TYPE_KPROBE \
                )

void *sandbox_alloc(const struct bpf_prog *prog, const void *kernel_ctx);
void sandbox_free(const struct bpf_prog *prog);
