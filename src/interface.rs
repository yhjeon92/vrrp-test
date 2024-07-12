use std::{
    io::{IoSlice, IoSliceMut},
    mem::size_of,
    net::Ipv4Addr,
    os::fd::{AsRawFd, OwnedFd},
};

use nix::sys::socket::{recvmsg, sendmsg, ControlMessage, MsgFlags, NetlinkAddr};

use crate::{
    constants::{
        AF_INET, IFA_ADDRESS, IFA_LABEL, IFA_LOCAL, IFR_FLAG_MULTICAST, IFR_FLAG_RUNNING,
        IFR_FLAG_UP, NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST, RTM_NEWADDR,
        RT_SCOPE_UNIVERSE,
    },
    packet::{IfAddrMessage, NetLinkAttributeHeader, NetLinkMessageHeader},
    socket::open_netlink_socket,
};

struct IfrFlags {
    _ifr_name: [u8; 16],
    ifr_flags: i16,
}

pub fn set_if_multicast_flag(sock_fd: &OwnedFd, if_name: &str) -> Result<(), String> {
    let interfaces = nix::net::if_::if_nameindex().unwrap();

    let mut if_found = false;

    for interface in interfaces.iter() {
        match interface.name().to_str() {
            Ok(name) => {
                if name == if_name {
                    if_found = true;
                    break;
                }
            }
            Err(_) => {}
        }
    }

    if !if_found {
        return Err(format!("No interface named {}", if_name));
    }

    let ifname_slice = &mut [0u8; 16];

    for (i, b) in if_name.as_bytes().iter().enumerate() {
        ifname_slice[i] = *b;
    }

    let mut if_opts = IfrFlags {
        _ifr_name: {
            let mut buf = [0u8; 16];
            buf.clone_from_slice(ifname_slice);
            buf
        },
        ifr_flags: 0,
    };

    unsafe {
        // UP (0x01), RUNNING (0x40), MULTICAST (0x1000)
        if_opts.ifr_flags |= IFR_FLAG_UP | IFR_FLAG_RUNNING | IFR_FLAG_MULTICAST;

        let res = nix::libc::ioctl(sock_fd.as_raw_fd(), nix::libc::SIOCSIFFLAGS, &mut if_opts);
        if res < 0 {
            return Err(format!(
                "Cannot manipulate network interface {}: {}",
                if_name,
                std::io::Error::last_os_error().to_string(),
            ));
        }

        return Ok(());
    }
}

pub fn add_ip_address(if_name: &str, address: Ipv4Addr) -> Result<(), String> {
    let nl_sock_fd = match open_netlink_socket() {
        Ok(fd) => fd,
        Err(err) => {
            return Err(err);
        }
    };

    let if_ind = match nix::net::if_::if_nametoindex(if_name) {
        Ok(ind) => ind,
        Err(err) => {
            return Err(err.to_string());
        }
    };

    let mut nl_msg = NetLinkMessageHeader::new(
        0,
        RTM_NEWADDR,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE,
        0,
        0,
    );

    let mut payload_bytes = Vec::<u8>::new();

    let ifa_msg = IfAddrMessage::new(
        AF_INET as u8,
        size_of::<NetLinkMessageHeader>() as u8,
        0u8,
        RT_SCOPE_UNIVERSE,
        if_ind,
    );

    payload_bytes.append(&mut ifa_msg.to_bytes());
    payload_bytes.append(
        &mut NetLinkAttributeHeader::new(
            (size_of::<NetLinkAttributeHeader>() + 4) as u16,
            IFA_LOCAL,
        )
        .to_bytes(&mut Vec::from(address.octets())),
    );

    let if_label = format!("{}:0001", if_name);

    payload_bytes.append(
        &mut NetLinkAttributeHeader::new(
            (size_of::<NetLinkAttributeHeader>() + if_label.len() + 1) as u16,
            IFA_LABEL,
        )
        .to_bytes(&mut Vec::from(if_label.as_bytes())),
    );

    payload_bytes.append(
        &mut NetLinkAttributeHeader::new(
            (size_of::<NetLinkAttributeHeader>() + 4) as u16,
            IFA_ADDRESS,
        )
        .to_bytes(&mut Vec::from(address.octets())),
    );

    let cmsg: [ControlMessage; 0] = [];

    let netlink_addr = NetlinkAddr::new(0, 0);

    match sendmsg::<NetlinkAddr>(
        nl_sock_fd.as_raw_fd(),
        &[IoSlice::new(nl_msg.to_bytes(&mut payload_bytes).as_slice())],
        &cmsg,
        MsgFlags::empty(),
        Some(&netlink_addr),
    ) {
        Ok(_len) => {}
        Err(err) => {
            println!("[ERROR] {}", err.to_string());
        }
    }

    let mut dummy: [u8; 1024] = [0u8; 1024];
    let recv_iovec_mut = IoSliceMut::new(&mut dummy);
    let mut recv_cmsg_buf = Vec::<u8>::new();

    let recv_result = match recvmsg::<NetlinkAddr>(
        nl_sock_fd.as_raw_fd(),
        &mut [recv_iovec_mut],
        Some(&mut recv_cmsg_buf),
        MsgFlags::intersection(MsgFlags::MSG_TRUNC, MsgFlags::MSG_PEEK),
    ) {
        Ok(data) => {
            for ind in 0..data.bytes {
                print!("{:02X?} ", dummy[ind]);
            }
            println!();
            match String::from_utf8(recv_cmsg_buf) {
                Ok(decoded) => decoded,
                Err(err) => {
                    println!("Parsing ERR {}", err.to_string());
                    return Err(err.to_string());
                }
            }
        }
        Err(err) => {
            println!("ERR {}", err.to_string());
            return Err(err.to_string());
        }
    };

    Ok(())
}
