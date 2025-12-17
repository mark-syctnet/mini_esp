#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/percpu.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>

#define MINI_PORT 50000

/* 定义 per-CPU stats 和 replay 窗口 */
struct mini_stats {
    u64 rx_ok;
    u64 rx_drop;
};

struct mini_replay {
    u64 seq;
    u64 bitmap;  // 64-bit replay window
};

static DEFINE_PER_CPU(struct mini_stats, mini_stats);
static DEFINE_PER_CPU(struct mini_replay, mini_replay);
static DEFINE_SPINLOCK(peer_lock);
static struct hlist_head peers[256];  // 支持多 peer，基于 UDP 端口哈希

struct peer {
    __u32 ip;
    __u16 port;
    struct mini_replay replay;
    struct hlist_node node;
};

/* 防重放窗口处理 */
static inline int check_replay(u64 seq, struct mini_replay *replay)
{
    if (seq <= replay->seq) {
        __u64 off = replay->seq - seq;
        if (off >= 64 || (replay->bitmap & (1ULL << off)))
            return 1;
        replay->bitmap |= (1ULL << off);
    } else {
        __u64 diff = seq - replay->seq;
        if (diff >= 64)
            replay->bitmap = 1;
        else
            replay->bitmap = (replay->bitmap << diff) | 1;
        replay->seq = seq;
    }
    return 0;
}

static unsigned int mini_nf_rx(void *priv,
                               struct sk_buff *skb,
                               const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct udphdr *udph;
    struct peer *p;
    struct mini_stats *st;
    struct mini_replay *replay;

    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_UDP)
        return NF_ACCEPT;

    udph = udp_hdr(skb);
    if (ntohs(udph->dest) != MINI_PORT)
        return NF_ACCEPT;

    /* 根据源IP和端口查找 peer */
    p = NULL;
    spin_lock(&peer_lock);
    hash_for_each(peers[udph->dest % 256], i, p, node) {
        if (p->ip == iph->saddr && p->port == udph->dest) {
            replay = &p->replay;
            break;
        }
    }
    spin_unlock(&peer_lock);

    if (!p) {
        return NF_ACCEPT;  // peer 不存在
    }

    /* 更新 stats */
    st = this_cpu_ptr(&mini_stats);
    st->rx_ok++;

    /* 防重放 */
    if (check_replay(be64toh(*(u64 *)skb->data), replay))
        return NF_DROP;

    return NF_ACCEPT;
}

static struct nf_hook_ops mini_nf_ops = {
    .hook = mini_nf_rx,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST,
};

static int __init mini_init(void)
{
    return nf_register_net_hook(&init_net, &mini_nf_ops);
}

static void __exit mini_exit(void)
{
    nf_unregister_net_hook(&init_net, &mini_nf_ops);
}

module_init(mini_init);
module_exit(mini_exit);
MODULE_LICENSE("GPL");
