#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

/* Required: bpf_skc_to_tcp_sock and struct tcp_sock access are GPL-only.
   Without this section the verifier rejects record_tcp_srtt at load time. */
char LICENSE[] SEC("license") = "GPL";

struct sock_common {
    __be32 skc_daddr;
    __be32 skc_rcv_saddr;
    __be16 skc_dport;
    __u16  skc_num;
} __attribute__((preserve_access_index));

struct sock {
    struct sock_common __sk_common;
} __attribute__((preserve_access_index));

struct msghdr;

struct tcp_sock {
    __u32 srtt_us;
} __attribute__((preserve_access_index));

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} netops_rx_bytes SEC(".maps");

SEC("tcx/ingress")
int count_rx(struct __sk_buff *skb)
{
    __u32 key = 0;
    __u64 *val = bpf_map_lookup_elem(&netops_rx_bytes, &key);
    if (val) {
        __sync_fetch_and_add(val, skb->len);
    }
    return TC_ACT_UNSPEC;
}

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} netops_tcp_retransmits SEC(".maps");

SEC("fentry/tcp_retransmit_skb")
int BPF_PROG(count_tcp_retransmit)
{
    __u32 key = 0;
    __u64 *val = bpf_map_lookup_elem(&netops_tcp_retransmits, &key);
    if (val) {
        __sync_fetch_and_add(val, 1);
    }
    return 0;
}

#define netops_SRTT_NUM_BUCKETS 24
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, netops_SRTT_NUM_BUCKETS);
    __type(key, __u32);
    __type(value, __u64);
} netops_tcp_srtt_buckets SEC(".maps");

SEC("fentry/tcp_rcv_established")
int BPF_PROG(record_tcp_srtt, struct sock *sk)
{
    struct tcp_sock *tsk = bpf_skc_to_tcp_sock(sk);
    if (!tsk) {
        return 0;
    }
    __u32 srtt_us = tsk->srtt_us;
    if (srtt_us == 0) {
        return 0;
    }

    __u32 bucket = 0;
    __u32 v = srtt_us;
    #pragma unroll
    for (__u32 i = 1; i < netops_SRTT_NUM_BUCKETS; i++) {
        v >>= 1;
        if (v) {
            bucket = i;
        }
    }

    __u64 *val = bpf_map_lookup_elem(&netops_tcp_srtt_buckets, &bucket);
    if (val) {
        __sync_fetch_and_add(val, 1);
    }
    return 0;
}

struct dns_flow_key {
    __be32 saddr;
    __be32 daddr;
    __u16  sport;
    __be16 dport;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct dns_flow_key);
    __type(value, __u64);
} netops_dns_query_starts SEC(".maps");

#define netops_DNS_NUM_BUCKETS 24
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, netops_DNS_NUM_BUCKETS);
    __type(key, __u32);
    __type(value, __u64);
} netops_dns_latency_buckets SEC(".maps");

static __always_inline void
dns_build_key(struct dns_flow_key *k, struct sock *sk)
{
    __builtin_memset(k, 0, sizeof(*k));
    k->saddr = sk->__sk_common.skc_rcv_saddr;
    k->daddr = sk->__sk_common.skc_daddr;
    k->sport = sk->__sk_common.skc_num;
    k->dport = sk->__sk_common.skc_dport;
}

SEC("fentry/udp_sendmsg")
int BPF_PROG(record_dns_query, struct sock *sk, struct msghdr *msg)
{
    if (sk->__sk_common.skc_dport != bpf_htons(53)) {
        return 0;
    }
    struct dns_flow_key key;
    dns_build_key(&key, sk);
    __u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&netops_dns_query_starts, &key, &now, BPF_ANY);
    return 0;
}

SEC("fexit/udp_recvmsg")
int BPF_PROG(record_dns_response, struct sock *sk, struct msghdr *msg,
             unsigned long len, int flags, int *addr_len, int ret)
{
    if (ret <= 0) {
        return 0;
    }
    if (sk->__sk_common.skc_dport != bpf_htons(53)) {
        return 0;
    }
    struct dns_flow_key key;
    dns_build_key(&key, sk);
    __u64 *start = bpf_map_lookup_elem(&netops_dns_query_starts, &key);
    if (!start) {
        return 0;
    }
    __u64 now = bpf_ktime_get_ns();
    __u64 t0 = *start;
    bpf_map_delete_elem(&netops_dns_query_starts, &key);

    if (now < t0) {
        return 0;
    }
    __u64 delta_us = (now - t0) / 1000;

    __u32 bucket = 0;
    __u64 v = delta_us;
    #pragma unroll
    for (__u32 i = 1; i < netops_DNS_NUM_BUCKETS; i++) {
        v >>= 1;
        if (v) {
            bucket = i;
        }
    }
    __u64 *cell = bpf_map_lookup_elem(&netops_dns_latency_buckets, &bucket);
    if (cell) {
        __sync_fetch_and_add(cell, 1);
    }
    return 0;
}
