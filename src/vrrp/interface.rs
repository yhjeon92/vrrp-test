use std::{
    convert::TryInto,
    io::{IoSlice, IoSliceMut},
    mem::size_of,
    net::Ipv4Addr,
    os::fd::{AsRawFd, OwnedFd},
};

use log::{debug, error};
use nix::{
    libc::{sockaddr, sockaddr_in},
    sys::socket::{recvmsg, sendmsg, ControlMessage, MsgFlags, NetlinkAddr},
};

use crate::vrrp::{
    constants::{
        AF_INET, IFA_ADDRESS, IFA_LOCAL, IFR_FLAG_MULTICAST, IFR_FLAG_RUNNING, IFR_FLAG_UP,
        NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST, RTM_DELADDR, RTM_NEWADDR,
        RT_SCOPE_UNIVERSE,
    },
    packet::{IfAddrMessage, NetLinkAttributeHeader, NetLinkMessageHeader},
    socket::{open_ip_socket, open_netlink_socket},
    Ipv4WithNetmask,
};

struct IfrFlags {
    _ifr_name: [u8; 16],
    ifr_flags: i16,
}

struct IfRequest {
    _ifr_name: [u8; 16],
    ifr_addr: [u8; 16], /* for AF_INET: sockaddr_in [ i16 sin_family - u16 sin_port ] */
}

pub fn get_if_index(if_name: &str) -> Result<u32, String> {
    match nix::net::if_::if_nametoindex(if_name) {
        Ok(index) => Ok(index),
        Err(errno) => Err(errno.to_string()),
    }
}

pub fn set_if_multicast_flag(sock_fd: &OwnedFd, if_name: &str) -> Result<(), String> {
    _ = match get_if_index(if_name) {
        Ok(_) => {}
        Err(err) => {
            return Err(err);
        }
    };

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

pub fn get_ip_address(if_name: &str) -> Result<Ipv4Addr, String> {
    /* check the interface of given name exists */
    _ = match get_if_index(if_name) {
        Ok(_) => {}
        Err(err) => {
            return Err(err);
        }
    };

    let ifname_slice = &mut [0u8; 16];

    for (i, b) in if_name.as_bytes().iter().enumerate() {
        ifname_slice[i] = *b;
    }

    let mut if_opts = IfRequest {
        _ifr_name: {
            let mut buf = [0u8; 16];
            buf.clone_from_slice(ifname_slice);
            buf
        },
        ifr_addr: [0u8; 16],
    };

    let sock_fd = match open_ip_socket() {
        Ok(fd) => fd,
        Err(err) => {
            return Err(err);
        }
    };

    unsafe {
        let res = nix::libc::ioctl(sock_fd.as_raw_fd(), nix::libc::SIOCGIFADDR, &mut if_opts);
        if res < 0 {
            return Err(format!(
                "Failed to get primary IPv4 address of interface {}: {}",
                if_name,
                std::io::Error::last_os_error().to_string(),
            ));
        }

        debug!(
            "{}",
            if_opts
                .ifr_addr
                .iter()
                .map(|byte| format!("{:02X?} ", byte))
                .collect::<String>()
        );

        let sockaddr =
            core::mem::transmute::<*mut [u8; 16], *mut sockaddr_in>(&mut if_opts.ifr_addr);

        if sockaddr.read().sin_family == AF_INET as u16 {
            let ipaddr_converted = Ipv4Addr::from(sockaddr.read().sin_addr.s_addr.to_ne_bytes());
            debug!("{}", ipaddr_converted.to_string());
            return Ok(Ipv4Addr::from(sockaddr.read().sin_addr.s_addr));
        } else {
            return Err(format!(
                "Wrong sin_family 0x{:04X?} from kernel system call response",
                sockaddr.read().sin_family
            ));
        }
    }
}

pub fn get_mac_address(if_name: &str) -> Result<[u8; 6], String> {
    /* check the interface of given name exists */
    _ = match get_if_index(if_name) {
        Ok(_) => {}
        Err(err) => {
            return Err(err);
        }
    };

    let ifname_slice = &mut [0u8; 16];

    for (i, b) in if_name.as_bytes().iter().enumerate() {
        ifname_slice[i] = *b;
    }

    let mut if_opts = IfRequest {
        _ifr_name: {
            let mut buf = [0u8; 16];
            buf.clone_from_slice(ifname_slice);
            buf
        },
        ifr_addr: [0u8; 16],
    };

    let sock_fd = match open_ip_socket() {
        Ok(fd) => fd,
        Err(err) => {
            return Err(err);
        }
    };

    unsafe {
        let res = nix::libc::ioctl(sock_fd.as_raw_fd(), nix::libc::SIOCGIFHWADDR, &mut if_opts);
        if res < 0 {
            return Err(format!(
                "Failed to query Hardware address for interface {}: {}",
                if_name,
                std::io::Error::last_os_error().to_string(),
            ));
        }

        debug!(
            "{}",
            if_opts
                .ifr_addr
                .iter()
                .map(|byte| format!("{:02X?} ", byte))
                .collect::<String>()
        );

        let sockaddr = core::mem::transmute::<*mut [u8; 16], *mut sockaddr>(&mut if_opts.ifr_addr);

        let hwaddr: [i8; 6] = sockaddr.read().sa_data[0..6].try_into().unwrap();
        let mut hwaddr_converted: [u8; 6] = [0u8; 6];

        for index in 0..6 {
            hwaddr_converted[index] = hwaddr[index] as u8;
        }

        debug!(
            "MAC converted: {}",
            hwaddr_converted
                .iter()
                .map(|byte| format!("{:02X?} ", byte))
                .collect::<String>()
        );

        Ok(hwaddr_converted)
    }
}

pub fn add_ip_address(if_name: &str, address: &Ipv4WithNetmask) -> Result<(), String> {
    let nl_sock_fd = match open_netlink_socket() {
        Ok(fd) => fd,
        Err(err) => {
            return Err(err);
        }
    };

    let if_ind = match get_if_index(if_name) {
        Ok(ind) => ind,
        Err(err) => {
            return Err(err);
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
        address.netmask,
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
        .to_bytes(&mut Vec::from(address.address.octets())),
    );

    payload_bytes.append(
        &mut NetLinkAttributeHeader::new(
            (size_of::<NetLinkAttributeHeader>() + 4) as u16,
            IFA_ADDRESS,
        )
        .to_bytes(&mut Vec::from(address.address.octets())),
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

pub fn del_ip_address(if_name: &str, address: &Ipv4WithNetmask) -> Result<(), String> {
    let nl_sock_fd = match open_netlink_socket() {
        Ok(fd) => fd,
        Err(err) => {
            return Err(err);
        }
    };

    let if_ind = match get_if_index(if_name) {
        Ok(ind) => ind,
        Err(err) => {
            return Err(err);
        }
    };

    let mut nl_msg = NetLinkMessageHeader::new(0, RTM_DELADDR, NLM_F_REQUEST | NLM_F_ACK, 0, 0);

    let mut payload_bytes = Vec::<u8>::new();

    let ifa_msg = IfAddrMessage::new(
        AF_INET as u8,
        address.netmask,
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
        .to_bytes(&mut Vec::from(address.address.octets())),
    );

    payload_bytes.append(
        &mut NetLinkAttributeHeader::new(
            (size_of::<NetLinkAttributeHeader>() + 4) as u16,
            IFA_ADDRESS,
        )
        .to_bytes(&mut Vec::from(address.address.octets())),
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
