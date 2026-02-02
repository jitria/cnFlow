#include "vmlinux.h"
#include "libbpf/src/bpf_core_read.h"
#include "libbpf/src/bpf_helpers.h"
#include "libbpf/src/bpf_tracing.h"
#include "libbpf/src/bpf_endian.h"

char __license[] SEC("license") = "GPL";

// TC action codes
#define TC_ACT_OK            0x00000000
#define TC_ACT_RECLASSIFY    0x00000001
#define TC_ACT_SHOT          0x00000002
#define TC_ACT_PIPE          0x00000003
#define TC_ACT_STOLEN        0x00000004
#define TC_ACT_QUEUED        0x00000005
#define TC_ACT_REPEAT        0x00000006
#define TC_ACT_REDIRECT      0x00000007
#define TC_ACT_JUMP          0x10000000

#define ETH_P_IP 0x0800 
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17