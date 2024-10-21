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
        AF_INET, CTRL_ATTR_FAMILY_ID, CTRL_ATTR_FAMILY_NAME, CTRL_CMD_GETFAMILY, CTRL_CMD_GETOPS,
        GENL_ID_CTRL, IFA_ADDRESS, IFA_LOCAL, IFR_FLAG_MULTICAST, IFR_FLAG_RUNNING, IFR_FLAG_UP,
        IPPROTO_TCP, IPVS_CMD_ATTR_SERVICE, IPVS_CMD_GET_SERVICE, IPVS_CMD_NEW_SERVICE,
        IPVS_SVC_ATTR_ADDR, IPVS_SVC_ATTR_AF, IPVS_SVC_ATTR_PORT, IPVS_SVC_ATTR_PROTOCOL,
        NLMSG_ERROR, NLMSG_HDR_SIZE, NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL,
        NLM_F_REQUEST, RTM_DELADDR, RTM_NEWADDR, RT_SCOPE_UNIVERSE,
    },
    packet::{
        parse_genl_ipvs, parse_genl_msg, GenericNetLinkMessageHeader, IfAddrMessage,
        NetLinkAttributeHeader, NetLinkMessageHeader,
    },
    socket::{
        open_genl_socket, open_ip_socket, open_netlink_socket, recv_netlink_message,
        send_netlink_message,
    },
    util::{byte_array_into_string, execute_command},
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
            return Ok(ipaddr_converted);
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

pub fn add_ipvs_service(address: &Ipv4Addr, port: u16) -> Result<(), String> {
    // init ip_vs module
    match execute_command("modprobe -va ip_vs".to_owned()) {
        Ok(()) => {}
        Err(err) => {
            return Err(format!("Failed to initialize ip_vs: {}", err));
        }
    }

    let sock_fd = match open_genl_socket() {
        Ok(fd) => fd,
        Err(err) => {
            return Err(err);
        }
    };

    let mut nl_msg = NetLinkMessageHeader::new(
        0,
        GENL_ID_CTRL,
        NLM_F_REQUEST | NLM_F_ACK, // For GETFAMILY
        0,
        0,
    );

    let mut payload_bytes = Vec::<u8>::new();

    // TODO
    payload_bytes.append(&mut GenericNetLinkMessageHeader::new(CTRL_CMD_GETFAMILY, 1).to_bytes());

    let family_name_attr = NetLinkAttributeHeader::new(
        (size_of::<NetLinkAttributeHeader>() + 5) as u16,
        CTRL_ATTR_FAMILY_NAME,
    );

    let mut family_name: Vec<u8> = Vec::<u8>::new();

    family_name.append(&mut "IPVS".as_bytes().to_vec());
    family_name.push(0u8);

    payload_bytes.append(&mut family_name_attr.to_bytes(&mut family_name));

    match send_netlink_message(sock_fd.as_raw_fd(), &mut nl_msg, &mut payload_bytes) {
        Ok(_len) => {}
        Err(err) => {
            return Err(err);
        }
    }

    let mut recv_buf: [u8; 1024] = [0u8; 1024];

    let mut nl_resp_hdr = match recv_netlink_message(sock_fd.as_raw_fd(), &mut recv_buf) {
        Ok(nlmsg_hdr) => nlmsg_hdr,
        Err(err) => {
            return Err(format!("Netlink recvmsg() error: {}", err));
        }
    };

    debug!("Bytes received: ");
    debug!(
        "{}",
        recv_buf[0..nl_resp_hdr.msg_len as usize]
            .iter()
            .map(|byte| format!("{:02X?} ", byte))
            .collect::<String>()
    );

    nl_resp_hdr.print();

    if nl_resp_hdr.msg_type == NLMSG_ERROR {
        debug!("{}", payload_bytes.len());

        payload_bytes
            .append(&mut GenericNetLinkMessageHeader::new(CTRL_CMD_GETFAMILY, 1).to_bytes());
        payload_bytes.append(&mut family_name_attr.to_bytes(&mut family_name));

        debug!("{}", payload_bytes.len());

        match send_netlink_message(sock_fd.as_raw_fd(), &mut nl_msg, &mut payload_bytes) {
            Ok(_len) => {
                nl_resp_hdr = match recv_netlink_message(sock_fd.as_raw_fd(), &mut recv_buf) {
                    Ok(nlmsg_hdr) => nlmsg_hdr,
                    Err(err) => {
                        return Err(format!("Netlink recvmsg() error: {}", err));
                    }
                };
            }
            Err(err) => {
                return Err(err);
            }
        }
    }

    let ipvs_family_id =
        match parse_genl_msg(&recv_buf[NLMSG_HDR_SIZE..nl_resp_hdr.msg_len as usize]) {
            Ok((_genl_hdr, attributes)) => match attributes.get(&CTRL_ATTR_FAMILY_ID) {
                Some(a) => u16::from_ne_bytes((**a)[0..2].try_into().unwrap()),
                None => {
                    return Err(
                        "Failed to read IPVS netlink family Id from netlink response".to_owned(),
                    );
                }
            },
            Err(err) => {
                return Err(format!("Failed to parse generic netlink response: {}", err));
            }
        };

    let mut recv_buf: [u8; 32768] = [0u8; 32768];

    // expect NLMSG_ERROR with flag NLM_F_CAPPED
    let _ = recv_netlink_message(sock_fd.as_raw_fd(), &mut recv_buf);

    nl_msg = NetLinkMessageHeader::new(
        0,
        ipvs_family_id,                         // IPVS
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP, // For IPVS
        0,
        0,
    );

    let mut ipvs_payload = Vec::<u8>::new();

    ipvs_payload.append(&mut GenericNetLinkMessageHeader::new(IPVS_CMD_GET_SERVICE, 1).to_bytes());

    match send_netlink_message(sock_fd.as_raw_fd(), &mut nl_msg, &mut ipvs_payload) {
        Ok(_len) => {}
        Err(err) => {
            error!("Socket sendmsg() failed: {}", err.to_string());
        }
    }

    // match sendmsg::<NetlinkAddr>(
    //     sock_fd.as_raw_fd(),
    //     &[IoSlice::new(nl_msg.to_bytes(&mut ipvs_payload).as_slice())],
    //     &cmsg,
    //     MsgFlags::empty(),
    //     Some(&netlink_addr),
    // ) {
    //     Ok(_len) => {}
    //     Err(err) => {
    //         error!("Socket sendmsg() failed: {}", err.to_string());
    //     }
    // }

    let mut recv_buf: [u8; 16384] = [0u8; 16384];
    let mut recv_cmsg_buf = Vec::<u8>::new();

    let resp_len = match recvmsg::<NetlinkAddr>(
        sock_fd.as_raw_fd(),
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

    let nl_resp_hdr = match NetLinkMessageHeader::from_slice(&recv_buf[0..NLMSG_HDR_SIZE]) {
        Some(hdr) => hdr,
        None => NetLinkMessageHeader::new(0, 0, 0, 0, 0),
    };

    nl_resp_hdr.print();

    match parse_genl_ipvs(&recv_buf[NLMSG_HDR_SIZE..resp_len]) {
        Ok((a, b)) => {
            for key in b.keys() {
                debug!("key:\t{}", key);
                debug!(
                    "value:\t{}",
                    b.get(key)
                        .iter()
                        .map(|byte| format!("{:02X?} ", byte))
                        .collect::<String>()
                );
            }
        }
        Err(err) => {
            error!("{}", err);
        }
    }

    // TODO: send IPVS_CMD_NEW_SERVICE
    nl_msg = NetLinkMessageHeader::new(
        0,
        ipvs_family_id,            // IPVS
        NLM_F_REQUEST | NLM_F_ACK, // For IPVS
        0,
        0,
    );

    let mut ipvs_payload = Vec::<u8>::new();

    ipvs_payload.append(&mut GenericNetLinkMessageHeader::new(IPVS_CMD_NEW_SERVICE, 1).to_bytes());

    // let mut ipvs_svc_attr = NetLinkAttributeHeader::new(0, IPVS_CMD_ATTR_SERVICE);

    let mut ipvs_nested_attrs: Vec<u8> = Vec::new();

    ipvs_nested_attrs.append(
        &mut NetLinkAttributeHeader::new(6, IPVS_SVC_ATTR_AF)
            .to_bytes(&mut AF_INET.to_ne_bytes().to_vec()),
    );

    ipvs_nested_attrs.append(
        &mut NetLinkAttributeHeader::new(6, IPVS_SVC_ATTR_PROTOCOL)
            .to_bytes(&mut IPPROTO_TCP.to_ne_bytes().to_vec()),
    );

    ipvs_nested_attrs.append(
        &mut NetLinkAttributeHeader::new(8, IPVS_SVC_ATTR_ADDR)
            .to_bytes(&mut address.octets().to_vec()),
    );

    ipvs_nested_attrs.append(
        &mut NetLinkAttributeHeader::new(6, IPVS_SVC_ATTR_PORT)
            .to_bytes(&mut port.to_ne_bytes().to_vec()),
    );

    let mut ipvs_svc_attr =
        NetLinkAttributeHeader::new((ipvs_nested_attrs.len() + 4) as u16, IPVS_CMD_ATTR_SERVICE);

    ipvs_payload.append(&mut ipvs_svc_attr.to_bytes(&mut ipvs_nested_attrs));

    match send_netlink_message(sock_fd.as_raw_fd(), &mut nl_msg, &mut ipvs_payload) {
        Ok(_len) => {}
        Err(err) => {
            error!("Socket sendmsg() failed: {}", err.to_string());
        }
    }

    // TODO: receive - parse response
    let resp_len = match recvmsg::<NetlinkAddr>(
        sock_fd.as_raw_fd(),
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

    let nl_resp_hdr = match NetLinkMessageHeader::from_slice(&recv_buf[0..NLMSG_HDR_SIZE]) {
        Some(hdr) => hdr,
        None => NetLinkMessageHeader::new(0, 0, 0, 0, 0),
    };

    nl_resp_hdr.print();

    // TODO: receive - parse response end

    match i32::from_ne_bytes(
        recv_buf[NLMSG_HDR_SIZE..NLMSG_HDR_SIZE + 4]
            .try_into()
            .unwrap(),
    ) {
        0 => Ok(()),
        errno => Err(std::io::Error::from_raw_os_error(-errno).to_string()),
    }
}

pub fn add_ip_address(if_name: &str, address: &Ipv4WithNetmask) -> Result<(), String> {
    let sock_fd = match open_netlink_socket() {
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

    match send_netlink_message(sock_fd.as_raw_fd(), &mut nl_msg, &mut payload_bytes) {
        Ok(_len) => {}
        Err(err) => {
            return Err(format!("Socket sendmsg() failed: {}", err.to_string()));
        }
    }

    let mut recv_buf: [u8; 1024] = [0u8; 1024];

    let nl_resp_hdr = match recv_netlink_message(sock_fd.as_raw_fd(), &mut recv_buf) {
        Ok(hdr) => {
            debug!("Bytes received: ");
            debug!(
                "{}",
                byte_array_into_string(&recv_buf[0..hdr.msg_len as usize])
            );
            hdr
        }
        Err(err) => {
            return Err(format!("Socket recvmsg() failed: {}", err.to_string()));
        }
    };

    nl_resp_hdr.print();

    match i32::from_ne_bytes(
        recv_buf[NLMSG_HDR_SIZE..NLMSG_HDR_SIZE + 4]
            .try_into()
            .unwrap(),
    ) {
        0 => Ok(()),
        errno => Err(std::io::Error::from_raw_os_error(-errno).to_string()),
    }
}

pub fn del_ip_address(if_name: &str, address: &Ipv4WithNetmask) -> Result<(), String> {
    let sock_fd = match open_netlink_socket() {
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

    match send_netlink_message(sock_fd.as_raw_fd(), &mut nl_msg, &mut payload_bytes) {
        Ok(_len) => {}
        Err(err) => {
            return Err(format!("Socket sendmsg() failed: {}", err.to_string()));
        }
    }

    let mut recv_buf: [u8; 1024] = [0u8; 1024];

    let nl_resp_hdr = match recv_netlink_message(sock_fd.as_raw_fd(), &mut recv_buf) {
        Ok(hdr) => {
            debug!("Bytes received: ");
            debug!(
                "{}",
                byte_array_into_string(&recv_buf[0..hdr.msg_len as usize])
            );
            hdr
        }
        Err(err) => {
            return Err(format!("Socket recvmsg() failed: {}", err.to_string()));
        }
    };

    nl_resp_hdr.print();

    match i32::from_ne_bytes(
        recv_buf[NLMSG_HDR_SIZE..NLMSG_HDR_SIZE + 4]
            .try_into()
            .unwrap(),
    ) {
        0 => Ok(()),
        errno => Err(std::io::Error::from_raw_os_error(-errno).to_string()),
    }
}
