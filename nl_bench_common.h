#pragma once

#define NETLINK_PROTO_BENCH (17)
#define NETLINK_GRP_BENCH (3)

struct NLBenchRequest {
    unsigned int msg_count;
    unsigned int payload_size;
};