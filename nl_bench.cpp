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

int create_netlink_socket();
int send_bench_request(int nl_sock, uint32_t msg_count, uint32_t payload_size);
int benchmark_netlink_read(int nl_sock, uint32_t msg_count, uint32_t payload_size, std::chrono::nanoseconds& elapsed_time);

int main(int argc, char **argv)
{
    int ret = 0;

    if (argc != 5) {
        printf("Usage: %s <msg-count> <payload-size> <iterations>\n", argv[0]);
        return 1;
    }

    uint32_t msg_count = std::atoi(argv[1]);
    uint32_t payload_size = std::atoi(argv[2]);
    uint32_t iterations = std::atoi(argv[3]);
    uint32_t role = std::atoi(argv[4]);
    printf("Starting test with receiving %u messages of size %u for %u interations (%u MB in total)\n\n",
        msg_count,
        payload_size,
        iterations,
        payload_size / 1024 / 1024 * msg_count * iterations);

    int sock_fd = create_netlink_socket();
    if (sock_fd < 0) {
        printf("Failed to create netlink socket. Exiting.\n");
        return 1;
    }

    printf("| Iteration | Time (Total, us) | Time (Single Read, us) |\n");
    printf("| --------- | ---------------- | ---------------------- |\n");

    uint64_t total_elapsed_time_us = 0;
    for (uint32_t iteration = 0; iteration < iterations; iteration++) {
        if (role == 0 && send_bench_request(sock_fd, msg_count, payload_size) < 0) {
            printf("Failed to send bench request. Exiting.\n");
            goto CLEANUP;
        }

        std::chrono::nanoseconds elapsed_time;
        if (role == 1 && benchmark_netlink_read(sock_fd, msg_count, payload_size, elapsed_time) < 0) {
            printf("Failed to run netlink read benchmarks. Exiting.\n");
            goto CLEANUP;
        }

        auto elapsed_time_us = std::chrono::duration_cast<std::chrono::microseconds>(elapsed_time).count();
        total_elapsed_time_us += elapsed_time_us;

        printf(
            "| #%-8u | %-16lu | %-22lu |\n",
            iteration,
            elapsed_time_us,
            elapsed_time_us / msg_count);
    }

    printf(
        "| %-9s | %-16lu | %-22lu |\n",
        "Total",
        total_elapsed_time_us,
        total_elapsed_time_us / msg_count / iterations);

CLEANUP:
    if (sock_fd >= 0) {
        close(sock_fd);
    }

    return ret;
}

int create_netlink_socket()
{
    int sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_PROTO_BENCH);
    static int group = NETLINK_GRP_BENCH;
    if (sock_fd < 0) {
        printf("socket: %s\n", strerror(errno));
        return -1;
    }

    struct sockaddr_nl src_addr = {0};
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();
    // src_addr.nl_groups = 0;

    int bind_err = bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr));
    if (bind_err < 0) {
        printf("bind: %s\n", strerror(errno));
        return -1;
    }

    if (setsockopt(sock_fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &group, sizeof(group)) < 0) {
        perror("setsockopt");
        return -1;
    }

    return sock_fd;
}

int send_bench_request(int nl_sock, uint32_t msg_count, uint32_t payload_size) {
    // Build netlink message.
    std::vector<char> buffer(NLMSG_SPACE(sizeof(NLBenchRequest)), 0);
    struct nlmsghdr *nlh = (struct nlmsghdr *)&buffer[0];
    nlh->nlmsg_len = (uint32_t)buffer.size();
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;

    NLBenchRequest req = {
        .msg_count = msg_count,
        .payload_size = payload_size
    };
    memcpy(NLMSG_DATA(nlh), &req, sizeof(NLBenchRequest));

    // Build the socket message with kernel as destination.
    struct sockaddr_nl dest_addr = {0};
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;    /* For Linux Kernel */
    dest_addr.nl_groups = 0; /* unicast */

    struct iovec iov;
    memset(&iov, 0, sizeof(iov));
    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    // Send request
    int send_request_err = sendmsg(nl_sock, &msg, 0);
    if (send_request_err < 0) {
        printf("sendmsg(): %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

int benchmark_netlink_read(
    int nl_sock,
    uint32_t msg_count,
    uint32_t payload_size,
    std::chrono::nanoseconds& elapsed_time)
{
    // Create read buffer
    std::vector<char> buffer(NLMSG_SPACE(payload_size), 0);

    struct nlmsghdr *nlh = (struct nlmsghdr *)&buffer[0];
    nlh->nlmsg_len = (uint32_t)buffer.size();
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;

    // Create socket message with kernel as destination.
    struct sockaddr_nl dest_addr = {0};
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = getpid();    /* For Linux Kernel */
    // dest_addr.nl_groups = 3; /* unicast */

    struct iovec iov;
    memset(&iov, 0, sizeof(iov));
    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    // Receive message
    auto start_time = std::chrono::high_resolution_clock::now();
    for (uint32_t i = 0; i < msg_count; i++) {
        int recv_err = recvmsg(nl_sock, &msg, 0);
        if (recv_err < 0) {
            printf("sendmsg(): %s\n", strerror(errno));
            return -1;
        }
    }

    // Calculate elapsed time
    auto end_time = std::chrono::high_resolution_clock::now();
    elapsed_time = end_time - start_time;

    return 0;
}