// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <linux/bitmap.h>
#include <linux/percpu.h>
#include <crypto/aead.h>
#include <linux/scatterlist.h>
#include <net/netlink.h>
#include <net/ip.h>

#define DRV "mini_esp_perf"
#define MINI_NL_FAMILY 31
#define MINI_AEAD "chacha20poly1305"
#define MINI_AEAD_KEYLEN 32
#define MINI_NONCE_LEN 12
#define MINI_TAG_LEN 16
#define MINI_REPLAY_WIN 64
#define MINI_DEF_TTL 64
#define TX_EPOCH_BATCH 1024

/* ================= per-cpu ctx ================= */
struct mini_cpu_ctx {
    struct aead_request *req;
    u8 nonce[MINI_NONCE_LEN];
};
static DEFINE_PER_CPU(struct mini_cpu_ctx, cpu_ctx);

/* ================= SA ================= */
struct mini_sa {
    /* policy */
    u32 mark;              /* TX mark / optional RX */
    __be32 peer_ip;        /* RX: peer src, TX: dst */
    __be16 udp_port;       /* local listen / dst */

    /* crypto */
    struct crypto_aead *aead;

    /* TX seq */
    atomic64_t tx_epoch;   /* global */
    u64 __percpu *tx_seq;  /* per-cpu local */

    /* RX replay */
    u64 rx_seq;
    unsigned long replay[BITS_TO_LONGS(MINI_REPLAY_WIN)];

    /* concurrency */
    spinlock_t rx_lock;    /* RX replay only */

    /* hash */
    struct hlist_node mark_hnode;
    struct hlist_node rx_hnode;
};

DEFINE_HASHTABLE(sa_mark_ht, 8);
DEFINE_HASHTABLE(sa_rx_ht, 8);

static inline u32 rx_hash(__be32 ip, __be16 port)
{
    return jhash_2words((u32)ip, (u32)port, 0);
}

static struct mini_sa *sa_lookup_mark(u32 mark)
{
    struct mini_sa *sa;
    rcu_read_lock();
    hash_for_each_possible_rcu(sa_mark_ht, sa, mark_hnode, mark) {
        if (sa->mark == mark) {
            rcu_read_unlock();
            return sa;
        }
    }
    rcu_read_unlock();
    return NULL;
}

static struct mini_sa *sa_lookup_rx(struct sk_buff *skb, struct udphdr *udph)
{
    struct mini_sa *sa;
    if (likely(skb->mark)) {
        sa = sa_lookup_mark(skb->mark);
        if (likely(sa))
            return sa;
    }
    rcu_read_lock();
    hash_for_each_possible_rcu(sa_rx_ht, sa, rx_hnode,
        rx_hash(ip_hdr(skb)->saddr, udph->dest)) {
        if (sa->peer_ip == ip_hdr(skb)->saddr && sa->udp_port == udph->dest) {
            rcu_read_unlock();
            return sa;
        }
    }
    rcu_read_unlock();
    return NULL;
}

/* ================= Replay ================= */
static bool replay_ok(struct mini_sa *sa, u64 seq)
{
    bool ok = false;
    spin_lock_bh(&sa->rx_lock);
    if (seq > sa->rx_seq) {
        u64 diff = seq - sa->rx_seq;
        if (diff >= MINI_REPLAY_WIN)
            bitmap_zero(sa->replay, MINI_REPLAY_WIN);
        else
            bitmap_shift_left(sa->replay, sa->replay, diff, MINI_REPLAY_WIN);
        sa->rx_seq = seq;
        set_bit(0, sa->replay);
        ok = true;
    } else {
        u64 off = sa->rx_seq - seq;
        if (off < MINI_REPLAY_WIN && !test_bit(off, sa->replay)) {
            set_bit(off, sa->replay);
            ok = true;
        }
    }
    spin_unlock_bh(&sa->rx_lock);
    return ok;
}

/* ================= AEAD helpers ================= */
static inline int mini_encrypt(struct mini_sa *sa, struct sk_buff *skb, u64 seq)
{
    struct mini_cpu_ctx *c = this_cpu_ptr(&cpu_ctx);
    struct scatterlist sg;
    memset(c->nonce, 0, MINI_NONCE_LEN);
    put_unaligned_be64(seq, c->nonce + 4);
    sg_init_one(&sg, skb->data, skb->len);
    aead_request_set_crypt(c->req, &sg, &sg, skb->len - MINI_TAG_LEN, c->nonce);
    aead_request_set_ad(c->req, 0);
    return crypto_aead_encrypt(c->req);
}

static inline int mini_decrypt(struct mini_sa *sa, struct sk_buff *skb, u64 seq)
{
    struct mini_cpu_ctx *c = this_cpu_ptr(&cpu_ctx);
    struct scatterlist sg;
    memset(c->nonce, 0, MINI_NONCE_LEN);
    put_unaligned_be64(seq, c->nonce + 4);
    sg_init_one(&sg, skb->data, skb->len);
    aead_request_set_crypt(c->req, &sg, &sg, skb->len - MINI_TAG_LEN, c->nonce);
    aead_request_set_ad(c->req, 0);
    return crypto_aead_decrypt(c->req);
}

/* ================= TX hook ================= */
static unsigned int tx_hook(void *priv, struct sk_buff *skb,
                            const struct nf_hook_state *state)
{
    struct mini_sa *sa;
    struct iphdr *oiph, *iph;
    struct udphdr *udph;
    u64 *pseq, seq;
    int headroom;

    if (unlikely(!skb || !skb->mark))
        return NF_ACCEPT;

    sa = sa_lookup_mark(skb->mark);
    if (unlikely(!sa))
        return NF_ACCEPT;

    /* avoid expensive clone */
    if (unlikely(skb_shared(skb)))
        return NF_ACCEPT;

    /* per-cpu seq */
    pseq = this_cpu_ptr(sa->tx_seq);
    if (unlikely(*pseq == 0))
        *pseq = atomic64_add_return(TX_EPOCH_BATCH, &sa->tx_epoch);
    seq = (*pseq)++;

    oiph = ip_hdr(skb);

    headroom = sizeof(struct iphdr) + sizeof(struct udphdr) + 8;
    if (skb_cow_head(skb, headroom))
        goto drop;

    if (skb_tailroom(skb) < MINI_TAG_LEN)
        if (pskb_expand_head(skb, 0, MINI_TAG_LEN, GFP_ATOMIC))
            goto drop;

    /* prepend seq */
    skb_push(skb, 8);
    put_unaligned_be64(cpu_to_be64(seq), skb->data);

    /* append tag */
    skb_put(skb, MINI_TAG_LEN);

    if (unlikely(mini_encrypt(sa, skb, seq)))
        goto drop;

    /* UDP */
    skb_push(skb, sizeof(*udph));
    udph = (struct udphdr *)skb->data;
    udph->source = 0;
    udph->dest = sa->udp_port;
    udph->len = htons(skb->len);
    udph->check = 0;

    /* IP */
    skb_push(skb, sizeof(*iph));
    iph = (struct iphdr *)skb->data;
    iph->version = 4;
    iph->ihl = sizeof(*iph) >> 2;
    iph->tos = 0;
    iph->tot_len = htons(skb->len);
    iph->id = 0;
    iph->frag_off = 0;
    iph->ttl = MINI_DEF_TTL;
    iph->protocol = IPPROTO_UDP;
    iph->saddr = oiph->saddr;
    iph->daddr = sa->peer_ip;
    iph->check = ip_fast_csum((u8 *)iph, iph->ihl);

    skb->mark = 0;
    skb->dev = state->out;
    ip_local_out(state->net, state->sk, skb);
    return NF_STOLEN;

drop:
    kfree_skb(skb);
    return NF_STOLEN;
}

/* ================= RX hook ================= */
static unsigned int rx_hook(void *priv, struct sk_buff *skb,
                            const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct udphdr *udph;
    struct mini_sa *sa;
    u64 seq;

    if (unlikely(!skb)) return NF_ACCEPT;
    if (!pskb_may_pull(skb, sizeof(struct iphdr))) return NF_ACCEPT;
    iph = ip_hdr(skb);
    if (iph->protocol != IPPROTO_UDP) return NF_ACCEPT;
    if (!pskb_may_pull(skb, iph->ihl*4 + sizeof(struct udphdr))) return NF_ACCEPT;

    udph = (void *)iph + iph->ihl*4;
    sa = sa_lookup_rx(skb, udph);
    if (unlikely(!sa)) return NF_ACCEPT;

    skb_pull(skb, iph->ihl*4 + sizeof(*udph));
    if (unlikely(skb->len < 8 + MINI_TAG_LEN)) return NF_DROP;

    seq = be64_to_cpu(*(__be64 *)skb->data);
    skb_pull(skb, 8);

    if (unlikely(!replay_ok(sa, seq))) return NF_DROP;
    if (unlikely(mini_decrypt(sa, skb, seq))) return NF_DROP;

    netif_rx(skb);
    return NF_STOLEN;
}

static struct nf_hook_ops ops[] = {
    { .hook = tx_hook, .pf = NFPROTO_IPV4, .hooknum = NF_INET_LOCAL_OUT, .priority = NF_IP_PRI_FIRST },
    { .hook = rx_hook, .pf = NFPROTO_IPV4, .hooknum = NF_INET_PRE_ROUTING, .priority = NF_IP_PRI_FIRST },
};

/* ================= Netlink ================= */
struct mini_nl_sa {
    u32 mark;
    __be32 peer_ip;
    __be16 udp_port;
    u8 key[MINI_AEAD_KEYLEN];
};

static struct sock *nlsk;

static void nl_recv(struct sk_buff *skb)
{
    struct nlmsghdr *nlh = nlmsg_hdr(skb);
    struct mini_nl_sa *u;
    struct mini_sa *sa;
    int cpu;

    if (nlh->nlmsg_len < sizeof(*nlh) + sizeof(*u)) return;
    u = nlmsg_data(nlh);

    sa = kzalloc(sizeof(*sa), GFP_KERNEL);
    if (!sa) return;

    sa->mark = u->mark;
    sa->peer_ip = u->peer_ip;
    sa->udp_port = u->udp_port;
    spin_lock_init(&sa->rx_lock);
    atomic64_set(&sa->tx_epoch, 0);

    sa->tx_seq = alloc_percpu(u64);
    if (!sa->tx_seq) goto err;

    sa->aead = crypto_alloc_aead(MINI_AEAD, 0, 0);
    if (IS_ERR(sa->aead)) goto err;
    if (crypto_aead_setkey(sa->aead, u->key, MINI_AEAD_KEYLEN)) goto err;
    if (crypto_aead_setauthsize(sa->aead, MINI_TAG_LEN)) goto err;

    for_each_possible_cpu(cpu) {
        struct mini_cpu_ctx *c = &per_cpu(cpu_ctx, cpu);
        c->req = aead_request_alloc(sa->aead, GFP_KERNEL);
        if (!c->req) goto err;
    }

    hash_add_rcu(sa_mark_ht, &sa->mark_hnode, sa->mark);
    hash_add_rcu(sa_rx_ht, &sa->rx_hnode, rx_hash(sa->peer_ip, sa->udp_port));
    return;
err:
    if (sa->tx_seq) free_percpu(sa->tx_seq);
    if (!IS_ERR_OR_NULL(sa->aead)) crypto_free_aead(sa->aead);
    kfree(sa);
}

static int __init mini_init(void)
{
    struct netlink_kernel_cfg cfg = { .input = nl_recv };
    nlsk = netlink_kernel_create(&init_net, MINI_NL_FAMILY, &cfg);
    if (!nlsk) return -ENOMEM;
    nf_register_net_hooks(&init_net, ops, ARRAY_SIZE(ops));
    pr_info(DRV " loaded (perf)\n");
    return 0;
}

static void __exit mini_exit(void)
{
    nf_unregister_net_hooks(&init_net, ops, ARRAY_SIZE(ops));
    netlink_kernel_release(nlsk);
    pr_info(DRV " unloaded\n");
}

module_init(mini_init);
module_exit(mini_exit);
MODULE_LICENSE("GPL");
