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

use std::any::Any;

use neli::{
    consts::{nl::NlmF, socket::NlFamily},
    genl::{AttrTypeBuilder, Genlmsghdr, GenlmsghdrBuilder, NlattrBuilder},
    neli_enum,
    nl::{NlPayload, Nlmsghdr},
    router::synchronous::{NlRouter, NlRouterReceiverHandle},
    socket::NlSocket,
    types::{Buffer, GenlBuffer},
    utils::Groups, Size, ToBytes
    // Size, ToBytes
};

use std::{io::Cursor};

/// Name of the Netlink family registered via Generic Netlink
const FAMILY_NAME: &str = "PROTO_BENCH";
const NETLINK_GROUPS: &str = "IPFIX";

/// Data we want to send to kernel.
// const ECHO_MSG: &str = "Some data that has `Nl` trait implemented, like &str";

// Implements the necessary trait for the "neli" lib on an enum called "NlFoobarXmplOperation".
// NlFoobarXmplOperation corresponds to "enum NlFoobarXmplCommand" in kernel module C code.
// Describes what callback function shall be invoked in the linux kernel module.
// This is for the "cmd" field in Generic Netlink header.
#[neli_enum(serialized_type = "u8")]
pub enum NlFoobarXmplOperation {
    Unspec = 0,
    Echo = 1,
}

impl neli::consts::genl::Cmd for NlFoobarXmplOperation {}

// Implements the necessary trait for the "neli" lib on an enum called "NlFoobarXmplAttribute".
// NlFoobarXmplAttribute corresponds to "enum NlFoobarXmplAttribute" in kernel module C code.
// Describes the value type to data mappings inside the generic netlink packet payload.
// This is for the Netlink Attributes (the actual payload) we want to send.
#[neli_enum(serialized_type = "u16")]
pub enum NlFoobarXmplAttribute {
    Unspec = 0,
    MsgCount = 1,
    PayloadSize = 2,
    IPFix = 3,
}

impl neli::consts::genl::NlAttrType for NlFoobarXmplAttribute {}

fn main() {
    let (sock, mut multicast) = NlRouter::connect(
        NlFamily::Generic,
        // 0 is pid of kernel -> socket is connected to kernel
        Some(0),
        Groups::empty(),
    )
    .unwrap();

    let group_id = sock.resolve_nl_mcast_group(FAMILY_NAME, NETLINK_GROUPS).unwrap();

    let _ = sock.add_mcast_membership(Groups::new_groups(&[group_id]));

    let family_id = sock.resolve_genl_family(FAMILY_NAME).unwrap();
    // let family_id = match res {
    //     Ok(id) => id,
    //     Err(e) => {
    //         eprintln!(
    //             "The Netlink family '{FAMILY_NAME}' can't be found. Is the kernel module loaded yet? neli-error='{e}'"
    //         );
    //         // Exit without error in order for Continuous Integration and automatic testing not to fail.
    //         // This is because in testing/build scenarios we do not have a Kernel module which we can load.
    //         return;
    //     }
    // };

    // println!("Generic family number is {family_id}");

    let count = NlattrBuilder::default()
        .nla_type(
            AttrTypeBuilder::default()
                // the type of the attribute. This is an u16 and corresponds
                // to an enum on the receiving side
                .nla_type(NlFoobarXmplAttribute::MsgCount)
                .build()
                .unwrap(),
        )
        .nla_payload(5)
        .build()
        .unwrap();
    let size = NlattrBuilder::default()
        .nla_type(
            AttrTypeBuilder::default()
                // the type of the attribute. This is an u16 and corresponds
                // to an enum on the receiving side
                .nla_type(NlFoobarXmplAttribute::PayloadSize)
                .build()
                .unwrap(),
        )
        .nla_payload(128)
        .build()
        .unwrap();
    let mut attrs = GenlBuffer::new();
    attrs.push(count);
    attrs.push(size);
    // 2) prepare Generic Netlink Header. The Generic Netlink Header contains the
    //    attributes (actual data) as payload.
    let gnmsghdr = GenlmsghdrBuilder::default()
        .cmd(NlFoobarXmplOperation::Echo)
        // You can evolve your application over time using different versions or ignore it.
        // Application specific; receiver can check this value and to specific logic
        .version(1)
        // actual payload
        .attrs(attrs.clone())
        .build()
        .unwrap();
    println!("Send to kernel: '{:?}'", attrs);


    for _ in 0..10 {
        // Send data
        let mut recv = sock
            .send::<_, _, u16, Genlmsghdr<NlFoobarXmplOperation, NlFoobarXmplAttribute>>(
                family_id,
                // You can use flags in an application specific way (e.g. ACK flag). It is up to you
                // if you check against flags in your Kernel module. It is required to add NLM_F_REQUEST,
                // otherwise the Kernel doesn't route the packet to the right Netlink callback handler
                // in your Kernel module. This might result in a deadlock on the socket if an expected
                // reply you are waiting for in a blocking way is never received.
                // Kernel reference: https://elixir.bootlin.com/linux/v5.10.16/source/net/netlink/af_netlink.c#L2487
                //
                // NlRouter automatically adds the REQUEST flag.
                NlmF::ACK,
                NlPayload::Payload(gnmsghdr.clone()),
            )
            .expect("Send must work");

        // // receive echo'ed message
        // let res: Nlmsghdr<u16, Genlmsghdr<NlFoobarXmplOperation, NlFoobarXmplAttribute>> =
        //     recv.next().expect("Should receive a message").unwrap();

        // /* USELESS, just note: this is always the case. Otherwise neli would have returned Error
        // if res.nl_type == family_id {
        //     println!("Received successful reply!");
        // }*/
        // let attr_handle = res.get_payload().unwrap().attrs().get_attr_handle();
        // let received = attr_handle
        //     .get_attr_payload_as_with_len::<String>(NlFoobarXmplAttribute::IPFix)
        //     .unwrap();
        // println!("Received from kernel: '{received}'");

        // let nlmsg = res.get_payload().unwrap();
        // let mut buffer = Cursor::new(vec![0; nlmsg.padded_size()]);
        // nlmsg.to_bytes(&mut buffer);
        // println!("Received from kernel: '{:?}'", buffer);

    }

    // let res  = multicast.next().expect("Should receive a message").unwrap();
    // let payload = res.get_payload().unwrap();
    // println!("Received from kernel: '{:?}'", payload);

    for next in multicast {
        let msg = next.expect("Should receive a message");
        let payload = msg.nl_payload();
        let mut buffer = Cursor::new(vec![0; payload.padded_size()]);
        payload.to_bytes(&mut buffer);

        println!("Received from kernel: '{:?}'", buffer);

        // let payload = msg.get_payload().unwrap();
        // let handle = payload.attrs().get_attr_handle();
        // let attr = handle.get_attr_payload_as_with_len::<String>(3).unwrap();
        // println!("Received from kernel: '{:?}'", attr);
    }


}