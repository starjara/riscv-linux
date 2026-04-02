#ifndef _LINUX_GBPF_H
#define _LINUX_GBPF_H

#include <linux/types.h>
#include <linux/bpf.h>

#define GBPF_PAGE_SIZE 4096
#define GBPF_CONTEXT_SIZE 512
#define GBPF_STACK_SIZE (GBPF_PAGE_SIZE - GBPF_CONTEXT_SIZE)

#define GBPF_CTX_BASE 0x80000000ULL
#define GBPF_PKT_BASE 0x90000000ULL
#define GBPF_PKT_MAX_PAGES  64
#define GBPF_MAP_BASE 0xA0000000ULL

#define GBPF_STK_SAVE_S11       0
#define GBPF_STK_SAVE_S10       8
#define GBPF_STK_OLD_HGATP     16
#define GBPF_STK_CTX_BASE      24
#define GBPF_STK_PKT_BASE      32
#define GBPF_STK_MAP_BASE      40
#define GBPF_ORG_CTX           48
#define GBPF_STK_HELPER_ID     56

#define GBPF_TR_FRAME_SIZE     64

struct page;


extern size_t gbpf_ctx_size_map[];

enum GBPF_MAP_TYPE {
  PKT,
  MAP,
};

struct gbpf_ops {
  int (*check_module)(void);
  int (*create_pgd)(struct bpf_prog *prog);
  int (*map)(struct bpf_prog *prog);
  int (*map_ext)(const struct bpf_prog *prog, const void *kaddr, size_t len, enum GBPF_MAP_TYPE type);
  void (*destroy_pgtable)(struct bpf_prog *prog);
  u32 (*get_vmid)(void);
  void (*inc_vmid)(void);
  void (*dec_vmid)(void);
};

// Module call related 
int gbpf_register_ops(const struct gbpf_ops *ops);
void gbpf_unregister_ops(const struct gbpf_ops *ops);

const struct gbpf_ops *pbpf_ops_get(void);

// Module functions
int gbpf_call_check_module(void);
int gbpf_call_create_pgd(struct bpf_prog *prog);
int gbpf_call_map(struct bpf_prog *prog);
int gbpf_call_map_ext(const struct bpf_prog *prog, const void *kaddr, size_t len, enum GBPF_MAP_TYPE type);
void gbpf_call_destroy_pgtable(struct bpf_prog *prog);
u32 gbpf_call_get_vmid(void);
void gbpf_call_inc_vmid(void);
void gbpf_call_dec_vmid(void);

void *gbpf_copy_ctx(const void *ctx, const struct bpf_prog *prog);

// Trampoline functions
u64 gbpf_helper_call_trampoline(u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5);


#endif /* _LINUX_GBPF_H  */
