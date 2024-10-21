#pragma once

#define NETLINK_PROTO_BENCH (17)
#define NETLINK_GRP_BENCH (3)
#define NETLINK_FAMILY_NAME "PROTO_BENCH"
#define NETLINK_GROUPS "IPFIX"

struct NLBenchRequest {
    unsigned int msg_count;
    unsigned int payload_size;
};