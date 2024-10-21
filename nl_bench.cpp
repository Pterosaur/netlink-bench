#include <cstdlib>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <vector>
#include <chrono>

#include <sys/socket.h>
#include <linux/netlink.h>

#include "nl_bench_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/attr.h>
#include <sys/socket.h>
#include <unistd.h>

#define NL_BENCH_CMD_ECHO 1
#define NL_BENCH_ATTR_MSG_COUNT 1
#define NL_BENCH_ATTR_PAYLOAD_SIZE 2


struct generic_netlink_msg {
    /** Netlink header comes first. */
    struct nlmsghdr n;
    /** Afterwards the Generic Netlink header */
    struct genlmsghdr g;
    /** Custom data. Space for Netlink Attributes. */
    char buf[256];
};

static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err,
				void *arg)
{
	int *ret = (int *)arg;

	*ret = err->error;
    printf("Error received\n");
	return NL_SKIP;
}

static int ack_handler(struct nl_msg *msg, void *arg)
{
	int *ack = (int *)arg;

	*ack = 1;
    printf("Ack received\n");
	return NL_STOP;
}

static int finish_handler(struct nl_msg *msg, void *arg)
{
	int *done = (int *)arg;

	*done = 1;
    printf("Finish received\n");
	return NL_SKIP;
}

static int handler(struct nl_msg *msg, void *arg)
{
    printf("Handler called\n");

    return NL_OK;
}

int main() {
    struct nl_sock *sock;
    struct nl_msg *msg;
    int family_id;
    int ret;
    
    // Initialize socket
    sock = nl_socket_alloc();
    if (!sock) {
        fprintf(stderr, "Failed to allocate socket.\n");
        return -1;
    }

    // Connect to Generic Netlink
    if (genl_connect(sock)) {
        fprintf(stderr, "Failed to connect to Generic Netlink.\n");
        nl_socket_free(sock);
        return -1;
    }
    genl_ctrl_resolve_grp(sock, NETLINK_FAMILY_NAME, NETLINK_GROUPS);

    // Resolve the family name to ID
    family_id = genl_ctrl_resolve(sock, NETLINK_FAMILY_NAME);
    if (family_id < 0) {
        fprintf(stderr, "Family name %s not resolved.\n", NETLINK_FAMILY_NAME);
        nl_socket_free(sock);
        return -1;
    }

    // Allocate a new message
    msg = nlmsg_alloc();
    if (!msg) {
        fprintf(stderr, "Failed to allocate netlink message.\n");
        nl_socket_free(sock);
        return -1;
    }

    // Construct the Generic Netlink message
    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id, 0, 0, NL_BENCH_CMD_ECHO, 1);

    // Add attributes to the message
    nla_put_u32(msg, NL_BENCH_ATTR_MSG_COUNT, 5);
    nla_put_u32(msg, NL_BENCH_ATTR_PAYLOAD_SIZE, 128);

    // Send the message
    ret = nl_send_auto(sock, msg);
    if (ret < 0) {
        fprintf(stderr, "Failed to send message: %s\n", nl_geterror(ret));
        nlmsg_free(msg);
        nl_socket_free(sock);
        return -1;
    }

    // Receive the response (blocking)
    nlmsg_free(msg);  // Free the message

    struct generic_netlink_msg nl_response_msg;

    // int nl_rxtx_length = recv(nl_socket_get_fd(sock), &nl_response_msg, sizeof(nl_response_msg), 0);
    // // Validate response message
    // if (!NLMSG_OK((&nl_response_msg.n), nl_rxtx_length)) {
    //     fprintf(stderr, "family ID request : invalid message\n");
    //     fprintf(stderr, "error validating family id request result: invalid length\n");
    //     return -1;
    // }
    // if (nl_response_msg.n.nlmsg_type == NLMSG_ERROR) { // error
    //     fprintf(stderr, "family ID request : receive error\n");
    //     fprintf(stderr, "error validating family id request result: receive error\n");
    //     return -1;
    // }

    struct nl_cb * cb = NULL;
    cb = nl_cb_alloc(NL_CB_CUSTOM);
    int err, done, rc;

	nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &done);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &done);
    nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, handler, NULL);

	while (!err && !done) {
		rc = nl_recvmsgs(sock, cb);
		if (rc) {
			fprintf(stderr, "Error receiving netlink message: %s",
								strerror(rc));
			break;
		}
        printf("Received message\n");
	}

    // ret = nl_recvmsgs(sock, cb);  // Process incoming messages
    // if (ret < 0) {
    //     fprintf(stderr, "Failed to receive response: %s\n", nl_geterror(ret));
    // } else {
    //     printf("Response received successfully. %d\n", ret);
    // }

    // Cleanup
    nl_socket_free(sock);
    return 0;
}
