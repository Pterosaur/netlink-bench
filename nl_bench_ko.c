#include <linux/module.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/netlink.h>
#include <net/net_namespace.h>
#include <net/genetlink.h>
#include "nl_bench_common.h"

struct sock *nl_sk = NULL;

static struct genl_family nl_bench_family;

enum {
    NL_BENCH_ATTR_UNSPEC,
    NL_BENCH_ATTR_MSG_COUNT,
    NL_BENCH_ATTR_PAYLOAD_SIZE,
    NL_BENCH_ATTR_IPFIX,
    __NL_BENCH_ATTR_MAX,
};
#define NL_BENCH_ATTR_MAX (__NL_BENCH_ATTR_MAX)

// Define commands
enum {
    NL_BENCH_CMD_UNSPEC,
    NL_BENCH_CMD_ECHO,
    __NL_BENCH_CMD_MAX,
};
#define NL_BENCH_CMD_MAX (__NL_BENCH_CMD_MAX)

// Define the policy for the attributes
static const struct nla_policy nl_bench_policy[NL_BENCH_ATTR_MAX + 1] = {
    [NL_BENCH_ATTR_MSG_COUNT] = { .type = NLA_U32 },
    [NL_BENCH_ATTR_PAYLOAD_SIZE] = { .type = NLA_U32 },
};

static int send_msg_to_user(struct genl_info *info, const char *payload, uint32_t payload_size) {
    struct sk_buff *skb_out;
    struct nlmsghdr *nlh;
    void *msg_head;
    int res;

    // Allocate new skb
    // skb_out = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
    skb_out = nlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
    if (!skb_out) {
        printk(KERN_ERR "Failed to allocate new skb\n");
        return -ENOMEM;
    }

    sprintf(payload, "Hello, World! %d", info->snd_seq);

    // nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, payload_size, 0);
    // NETLINK_CB(skb_out).portid = 0;
    // NETLINK_CB(skb_out).dst_group = NETLINK_GRP_BENCH;
    // memcpy(nlmsg_data(nlh), payload, payload_size);


    res = nla_put_nohdr(skb_out, payload_size, payload);

    // // // Create the message
    // msg_head = genlmsg_put(skb_out, info->snd_portid, info->snd_seq, &nl_bench_family, 0, NL_BENCH_CMD_ECHO);
    // if (!msg_head) {
    //     printk(KERN_ERR "Failed to create the message\n");
    //     nlmsg_free(skb_out);
    //     return -ENOMEM;
    // }
    // // Add the payload
    // // memcpy(payload, "Hello, World!", 14);
    // res = nla_put(skb_out, NL_BENCH_ATTR_IPFIX, payload_size, payload);
    // // res = nla_put(skb_out, NL_BENCH_ATTR_PAYLOAD_SIZE, payload_size, payload);

    // if (res) {
    //     printk(KERN_ERR "Failed to add payload to the message\n");
    //     nlmsg_free(skb_out);
    //     return res;
    // }

    // // // Finalize the message
    // genlmsg_end(skb_out, msg_head);


    // Send the message
    // res = genlmsg_reply(skb_out, info);

    // skb_out = nlmsg_new(payload_size, GFP_KERNEL);
    // if (!skb_out) {
    //     printk(KERN_ERR "Failed to allocate new skb\n");
    //     return -ENOMEM;
    // }
    // memcpy(nlmsg_data(nlmsg_hdr(skb_out)), payload, payload_size);
    // nlmsg_unicast(nl_sk, skb_out, info->nlhdr->nlmsg_pid);




    res = genlmsg_multicast(&nl_bench_family, skb_out, 0, 0, GFP_KERNEL);

    if (res == -ESRCH)
    {
        pr_warn("multicast message sent, but nobody was listening...\n");
    }
    else if (res)
    {
        pr_err("failed to send multicast genl message\n");
    }
    else
    {
        pr_info("multicast message sent\n");
    }

    printk(KERN_INFO "Sent message to user-space: pid=%u port=%u MsgId = %u\n", info->nlhdr->nlmsg_pid, info->snd_portid, info->snd_seq);

    // nlmsg_free(skb_out);
    return 0;
}

static int nl_bench_echo(struct sk_buff *skb, struct genl_info *info) {
    uint32_t msg_count, payload_size;
    uint32_t i;
    char *msg_payload;
    int res;

    if (!info->attrs[NL_BENCH_ATTR_MSG_COUNT] || !info->attrs[NL_BENCH_ATTR_PAYLOAD_SIZE]) {
        printk(KERN_ERR "Required attributes missing\n");
        return -EINVAL;
    }

    msg_count = nla_get_u32(info->attrs[NL_BENCH_ATTR_MSG_COUNT]);
    payload_size = nla_get_u32(info->attrs[NL_BENCH_ATTR_PAYLOAD_SIZE]);

    printk(KERN_INFO "Netlink bench request received: MsgCount = %u, PayloadSize = %u\n", msg_count, payload_size);

    msg_payload = kmalloc(payload_size, GFP_KERNEL);
    if (!msg_payload) {
        printk(KERN_ERR "Failed to allocate message payload\n");
        return -ENOMEM;
    }

    // for (i = 0; i < msg_count; i++) {
        res = send_msg_to_user(info, msg_payload, payload_size);
        if (res < 0) {
            printk(KERN_ERR "Failed to send message to user-space\n");
            return res;
        }
    // }

    kfree(msg_payload);

    return 0;
}

static const struct genl_ops nl_bench_ops[] = {
    {
        .cmd = NL_BENCH_CMD_ECHO,
        .flags = 0,
        .policy = nl_bench_policy,
        .doit = nl_bench_echo,
    },
};

struct genl_multicast_group nl_bench_mcgrps[] = {
    { .name = NETLINK_GROUPS },
};

// Family definition
static struct genl_family nl_bench_family = {
    .name = NETLINK_FAMILY_NAME,
    .version = 1,
    .maxattr = NL_BENCH_ATTR_MAX,
    .netnsok = true,
    .module = THIS_MODULE,
    .ops = nl_bench_ops,
    .n_ops = ARRAY_SIZE(nl_bench_ops),
    .mcgrps = nl_bench_mcgrps,
    .n_mcgrps = ARRAY_SIZE(nl_bench_mcgrps),
};

static int __init nl_init(void) {

    printk(KERN_INFO "Initializing Netlink Kernel Module\n");

    int res = genl_register_family(&nl_bench_family);
    if (res) {
        printk(KERN_ALERT "Error registering family.\n");
        return res;
    }

    return 0;
}

static void __exit nl_exit(void) {
    printk(KERN_INFO "Exiting Netlink Kernel Module\n");

    genl_unregister_family(&nl_bench_family);
    return;
}

module_init(nl_init);
module_exit(nl_exit);

MODULE_LICENSE("MIT");
MODULE_AUTHOR("r12f");
MODULE_DESCRIPTION("Netlink Module for benchmark");
