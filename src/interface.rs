use std::{
    ffi::c_void,
    io::{IoSlice, IoSliceMut},
    net::Ipv4Addr,
    os::fd::{AsRawFd, OwnedFd},
    str::FromStr,
};

use nix::{
    ioctl_write_ptr,
    libc::{in_addr, msghdr, sockaddr, sockaddr_in, sockaddr_nl},
    sys::socket::{recvmsg, sendmsg, ControlMessage, LinkAddr, MsgFlags, SockaddrIn},
};

use crate::{
    constants::{
        AF_INET, IFA_ADDRESS, IFA_LABEL, IFA_LOCAL, IFR_FLAG_MULTICAST, IFR_FLAG_RUNNING,
        IFR_FLAG_UP, NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST, RTM_NEWADDR,
        RT_SCOPE_UNIVERSE,
    },
    packet::{IfAddrMessage, NetLinkMessage},
    socket::open_netlink_socket,
};

struct IOctlFlags {
    ifr_name: [u8; 16],
    ifr_flags: i16,
}

struct IfrFlags {
    ifr_name: [u8; 16],
    ifr_addr: sockaddr_in,
}

pub fn set_if_multicast_flag(sock_fd: &OwnedFd, if_name: &str) -> Result<bool, String> {
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

    let mut if_opts = IOctlFlags {
        ifr_name: {
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

        return Ok(true);
    }
}

pub fn add_ip_address(sock_fd: &OwnedFd, if_name: &str, address: Ipv4Addr) -> Result<bool, String> {
    let nl_sock_fd = match open_netlink_socket() {
        Ok(fd) => fd,
        Err(err) => {
            return Err(err);
        }
    };

    println!("Netlink Socket opened: {}", nl_sock_fd.as_raw_fd());

    let if_ind = match nix::net::if_::if_nametoindex(if_name) {
        Ok(ind) => ind,
        Err(err) => {
            return Err(err.to_string());
        }
    };

    println!("if_ind: {}", if_ind);

    let mut ifa_msg = IfAddrMessage::new(AF_INET as u8, 16u8, 0u8, RT_SCOPE_UNIVERSE, if_ind);

    let mut nl_msg = NetLinkMessage::new(
        56,
        RTM_NEWADDR,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE,
        0,
        0,
    );

    nl_msg.add_attribute(8u16, IFA_LOCAL as u16, Vec::from(address.octets()));

    let mut if_label = if_name.to_owned();
    if_label.push_str(":1 ");

    nl_msg.add_attribute(
        // ?
        (if_label.as_bytes().len() + 4) as u16,
        IFA_LABEL as u16,
        Vec::from(if_label.as_bytes()),
    );

    nl_msg.add_attribute(8u16, IFA_ADDRESS as u16, Vec::from(address.octets()));

    // nl_msg.to_bytes(&mut ifa_msg.to_bytes());
    let cmsg: [ControlMessage; 0] = [];

    let netlink_addr = nix::sys::socket::NetlinkAddr::new(0, 0);

    match sendmsg::<nix::sys::socket::NetlinkAddr>(
        nl_sock_fd.as_raw_fd(),
        &[IoSlice::new(
            nl_msg.to_bytes(&mut ifa_msg.to_bytes()).as_slice(),
        )],
        &cmsg,
        MsgFlags::empty(),
        Some(&netlink_addr),
    ) {
        Ok(len) => {
            println!("Sent succesfully: {} bytes", len);
        }
        Err(err) => {
            println!("[ERROR] {}", err.to_string());
        }
    }

    let mut dummy: [u8; 1024] = [0u8; 1024];
    let recv_iovec_mut = IoSliceMut::new(&mut dummy);
    let mut recv_cmsg_buf = Vec::<u8>::new();

    let recv_result = match recvmsg::<nix::sys::socket::NetlinkAddr>(
        nl_sock_fd.as_raw_fd(),
        &mut [recv_iovec_mut],
        Some(&mut recv_cmsg_buf),
        MsgFlags::MSG_TRUNC,
    ) {
        Ok(data) => match String::from_utf8(recv_cmsg_buf) {
            Ok(decoded) => decoded,
            Err(err) => {
                println!("Parsing ERR {}", err.to_string());
                return Err(err.to_string());
            }
        },
        Err(err) => {
            println!("ERR {}", err.to_string());
            return Err(err.to_string());
        }
    };

    // sendmsg(fd, iov, cmsgs, flags, addr)

    // match sendmsg(nl_sock_fd.as_raw_fd(), iov, (), MsgFlags::empty(), addr) {
    //     Ok(len) => {
    //         println!("{}", len);
    //     }
    //     Err(err) => {
    //         return Err(err.to_string());
    //     }
    // }

    Ok(true)
}
