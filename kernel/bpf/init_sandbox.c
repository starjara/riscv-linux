#include <linux/init_sandbox.h>
#include <linux/bpf_ctx.h>
#include <linux/bpf_mte.h>
#include <linux/hashtable.h>
#include <asm/bpf_sandbox.h>
#include <linux/bpf_sandbox.h>

void *sandbox_alloc(const struct bpf_prog *prog, const void *kernel_ctx)
{
        size_t ctx_size;

        pr_info("Sandbox allocation\n");

        if (kernel_ctx) {
                ctx_size = bpf_ctx_size_map[prog->type]; // TODO: change this to bpf ctx size
                current_sandbox_info->kern_ctx = (u64)kernel_ctx;
                bpf_sandbox_init_meminfo(current_sandbox_info, ctx_size);
#ifdef CONFIG_BPF_SANDBOX_CTX
                if (IS_SANDBOX_CTX_SUPPORTED(prog->type))
                        bpf_create_prog_ctx(prog, kernel_ctx, current_sandbox_mem);
                else
                        memcpy(current_sandbox_mem, kernel_ctx, ctx_size);
#else
                memcpy(current_sandbox_mem, kernel_ctx, ctx_size);
#endif /* CONFIG_BPF_SANDBOX_CTX */
        } else {
                bpf_sandbox_init_meminfo(current_sandbox_info, 0);
        }

        sandbox_ctx = current_sandbox_mem;
        bpf_sandbox_set_memory(current_sandbox_mem, current_sandbox_info->kern_ctx,
                               current_sandbox_info->or_mask, bpf_sandbox_and_mask);

        return current_sandbox_mem;
}

/**
 * sandbox_free() - Performs ctx syncing and (supposedly sandbox cleanup) upon exit
 *
 * @prog: bpf program pointer
 */
void sandbox_free(const struct bpf_prog *prog)
{
//  pr_info("Sandbox free\n");
#ifdef CONFIG_BPF_SANDBOX_CTX
        bpf_sync_kernel_ctx(prog, (void *)current_sandbox_info->kern_ctx, current_sandbox_mem);
#endif /* CONFIG_BPF_SANDBOX_CTX */
}

EXPORT_SYMBOL_GPL(sandbox_alloc);
EXPORT_SYMBOL_GPL(sandbox_free);
