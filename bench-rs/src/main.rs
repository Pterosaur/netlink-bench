//! Userland component written in Rust, that uses neli to talk to a custom Netlink
//! family via Generic Netlink. The family is called "gnl_foobar_xmpl" and the
//! kernel module must be loaded first. Otherwise the family doesn't exist.
//!
//! A working kernel module implementation with which you can use this binary
//! can be found here: https://github.com/phip1611/generic-netlink-user-kernel-rust
//!
//! Output might look like this (if the kernel module is loaded)
//! ```
//! Generic family number is 35
//! Send to kernel: 'Some data that has `Nl` trait implemented, like &str'
//! Received from kernel: 'Some data that has `Nl` trait implemented, like &str'
//! ```

// use std::iter::once;

use neli::{
    consts::socket::{Msg, NlFamily},
    router::synchronous::NlRouter,
    socket::NlSocket,
    // socket::synchronous::NlSocketHandle,
    utils::Groups,
};

/// Name of the Netlink family registered via Generic Netlink
const FAMILY_NAME: &str = "PROTO_BENCH";
const NETLINK_GROUPS: &str = "IPFIX";

fn main() {
    let (sock, _) = NlRouter::connect(
        NlFamily::Generic,
        // 0 is pid of kernel -> socket is connected to kernel
        Some(0),
        Groups::empty(),
    )
    .unwrap();

    let group_id = sock.resolve_nl_mcast_group(FAMILY_NAME, NETLINK_GROUPS).unwrap();

    let sock = NlSocket::connect(
        NlFamily::Generic,
        // 0 is pid of kernel -> socket is connected to kernel
        Some(0),
        Groups::empty(),
    )
    .unwrap();

    let _ = sock.add_mcast_membership(Groups::new_groups(&[group_id]));

    let mut buf = vec![0; 1024];
    while sock.recv(&mut buf, Msg::empty()).unwrap().0 > 0 {
        println!("{:?}", buf);
    }

}