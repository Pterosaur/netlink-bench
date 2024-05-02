#include <linux/module.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/netlink.h>
#include <net/net_namespace.h>
#include "nl_bench_common.h"

struct sock *nl_sk = NULL;

// Function to send a message to user-space
static int send_msg_to_user(int pid, const char* payload, uint32_t payload_size) {
    struct nlmsghdr *nlh;
    struct sk_buff *skb_out;
    int res;

    // Craft the message
    skb_out = nlmsg_new(payload_size, 0);
    if (!skb_out) {
        printk(KERN_ERR "Failed to allocate new skb for reply\n");
        return -1;
    }

    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, payload_size, 0);
    NETLINK_CB(skb_out).dst_group = 0;
    memcpy(nlmsg_data(nlh), payload, payload_size);

    // Send the message back
    res = nlmsg_unicast(nl_sk, skb_out, pid);
    if (res < 0) {
        printk(KERN_INFO "Error while sending back to user: %d\n", res);
        return -1;
    }

    return 0;
}

// Function to be called when a message is received from user-space
static void nl_recv_msg(struct sk_buff *skb) {
    struct nlmsghdr *nlh;
    struct NLBenchRequest *req;
    int pid;
    unsigned int msg_id;
    char* msg_paylaod = NULL;

    // Parse the request
    nlh = (struct nlmsghdr *)skb->data;
    pid = nlh->nlmsg_pid;
    req = (struct NLBenchRequest *)nlmsg_data(nlh);
    printk(KERN_INFO "Netlink bench request received: Pid = %u, MsgCount = %u, PayloadSize = %u\n", pid, req->msg_count, req->payload_size);

    // Allocate buffer
    msg_paylaod = kmalloc(req->payload_size, GFP_KERNEL);

    // Craft netlink message and send them back to user-space
    for (msg_id = 0; msg_id < req->msg_count; msg_id++) {
        if (send_msg_to_user(pid, msg_paylaod, req->payload_size) < 0) {
            printk(KERN_ERR "Failed to send message to user-space: MsgId = %u\n", msg_id);
            break;
        }
    }
}

static int __init nl_init(void) {
    printk(KERN_INFO "Initializing Netlink Kernel Module\n");
    struct netlink_kernel_cfg cfg = {
        .input = nl_recv_msg,
    };

    nl_sk = netlink_kernel_create(&init_net, NETLINK_PROTO_BENCH, &cfg);
    if (!nl_sk) {
        printk(KERN_ALERT "Error creating socket.\n");
        return -10;
    }

    return 0;
}

static void __exit nl_exit(void) {
    printk(KERN_INFO "Exiting Netlink Kernel Module\n");
    netlink_kernel_release(nl_sk);
}

module_init(nl_init);
module_exit(nl_exit);

MODULE_LICENSE("MIT");
MODULE_AUTHOR("r12f");
MODULE_DESCRIPTION("Netlink Module for benchmark");
