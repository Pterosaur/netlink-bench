use netlink_sys::{Socket, protocols::NETLINK_GENERIC};
use core::str;
use std::io;
// use std::os::unix::io::AsRawFd;
use bytes::{Buf, BufMut, BytesMut};
// use libc::NLM_F_REQUEST;

// Replace with your family and group names.
const GENL_FAMILY_NAME: &str = "PROTO_BENCH";
const GENL_GROUP_NAME: &str = "IPFIX";

/// Receive Generic Netlink messages from the kernel.
fn listen_genetlink_messages(socket: &mut Socket) -> io::Result<()> {
    let mut buffer = BytesMut::with_capacity(4096); // Use `BytesMut` as the buffer.

    loop {
        // Receive message synchronously.
        let nbytes = socket.recv(&mut buffer, 0)?; // Pass 0 as the flags.
        println!("Received {} bytes", nbytes);

        handle_raw_message(&buffer[..nbytes]);
        buffer.clear(); // Clear the buffer for the next message.
    }
}

/// Handle the raw Netlink message payload.
fn handle_raw_message(data: &[u8]) {
    println!("Raw Message: {:?}", data);

    if let Ok(text) = std::str::from_utf8(data) {
        println!("Decoded Message: {}", text);
    } else {
        println!("Non-UTF-8 message received.");
    }
}

/// Query the family and group ID by name.
fn get_family_and_group_id(socket: &mut Socket) -> io::Result<(u16, u32)> {
    let mut request = BytesMut::with_capacity(1024);

    // Create a Generic Netlink control request for family information.
    let hdr = libc::nlmsghdr {
        nlmsg_len: (std::mem::size_of::<libc::nlmsghdr>() + GENL_FAMILY_NAME.len() + 1) as u32,
        nlmsg_type: 16, // CTRL_CMD_GETFAMILY
        nlmsg_flags: libc::NLM_F_REQUEST as u16,
        nlmsg_seq: 1,
        nlmsg_pid: 0,
    };

    request.put_slice(unsafe {
        std::slice::from_raw_parts(&hdr as *const _ as *const u8, std::mem::size_of::<libc::nlmsghdr>())
    });
    request.put_slice(GENL_FAMILY_NAME.as_bytes());
    request.put_u8(0); // Null terminator.

    socket.send(&request, 0)?; // Pass 0 as the flags.

    let mut response = BytesMut::with_capacity(4096);
    let n = socket.recv(&mut response, 0)?; // Pass 0 as the flags.

    let mut buf = &response[..n];

    let family_id = buf.get_u16(); // Assuming family ID is at the start.

    // Iterate through attributes to find multicast group IDs.
    let mut group_id = None;
    while buf.remaining() >= 4 {
        let attr_type = buf.get_u16(); // Attribute type
        let attr_len = buf.get_u16();  // Attribute length

        if attr_type == libc::CTRL_ATTR_MCAST_GROUPS as u16 {
            let group_name = str::from_utf8(buf).unwrap();
            let id = buf.get_u32();

            println!("Found group: {} with ID: {}", group_name, id);
            if group_name == GENL_GROUP_NAME {
                group_id = Some(id);
                break;
            }
        } else {
            // Skip the attribute data if it's not what we need.
            buf.advance(attr_len as usize - 4);
        }
    }


    let group_id = group_id.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Group not found"))?;


    Ok((family_id, group_id))
}


fn main() -> io::Result<()> {
    // Create a Netlink socket for Generic Netlink communication.
    let mut socket = Socket::new(NETLINK_GENERIC)?;

    // Get the family and group IDs.
    let (family_id, group_id) = get_family_and_group_id(&mut socket)?;

    // Join the multicast group using the retrieved group ID.
    socket.add_membership(group_id)?;

    println!(
        "Listening for messages from family ID {} on group ID {}...",
        family_id, group_id
    );

    // Start listening for messages.
    listen_genetlink_messages(&mut socket)?;

    Ok(())
}
