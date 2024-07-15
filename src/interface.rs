use std::{
    convert::TryInto,
    io::{IoSlice, IoSliceMut},
    mem::size_of,
    net::Ipv4Addr,
    os::fd::{AsRawFd, OwnedFd},
};

use log::{debug, error};
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

pub fn get_if_index(if_name: &str) -> Result<u32, String> {
    match nix::net::if_::if_nametoindex(if_name) {
        Ok(index) => Ok(index),
        Err(errno) => Err(errno.to_string()),
    }
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

    let if_ind = match get_if_index(if_name) {
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

    let if_label = format!("{}:1", if_name);

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
            error!("Socket sendmsg() failed: {}", err.to_string());
        }
    }

    let mut recv_buf: [u8; 1024] = [0u8; 1024];
    let mut recv_cmsg_buf = Vec::<u8>::new();

    let resp_len = match recvmsg::<NetlinkAddr>(
        nl_sock_fd.as_raw_fd(),
        &mut [IoSliceMut::new(&mut recv_buf)],
        Some(&mut recv_cmsg_buf),
        MsgFlags::intersection(MsgFlags::MSG_TRUNC, MsgFlags::MSG_PEEK),
    ) {
        Ok(data) => data.bytes,
        Err(err) => {
            return Err(err.to_string());
        }
    };

    debug!("Bytes received: ");
    debug!(
        "{}",
        recv_buf[0..resp_len]
            .iter()
            .map(|byte| format!("{:02X?} ", byte))
            .collect::<String>()
    );

    const NLMSGHDR_SIZE: usize = size_of::<NetLinkMessageHeader>();

    let nl_resp_hdr = match NetLinkMessageHeader::from_slice(&recv_buf[0..NLMSGHDR_SIZE]) {
        Some(hdr) => hdr,
        None => NetLinkMessageHeader::new(0, 0, 0, 0, 0),
    };

    nl_resp_hdr.print();

    match i32::from_ne_bytes(
        recv_buf[NLMSGHDR_SIZE..NLMSGHDR_SIZE + 4]
            .try_into()
            .unwrap(),
    ) {
        0 => Ok(()),
        errno => Err(std::io::Error::from_raw_os_error(-errno).to_string()),
    }
}
