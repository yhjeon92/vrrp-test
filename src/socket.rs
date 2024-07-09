use std::{
    ffi::OsString,
    net::Ipv4Addr,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

use crate::{
    constants::{
        AF_INET, AF_PACKET, ETH_PROTO_ARP, IFR_FLAG_MULTICAST, IFR_FLAG_RUNNING, IFR_FLAG_UP,
        IPPROTO_VRRPV2, SOCKET_TTL, SOCK_RAW, VRRP_MCAST_ADDR,
    },
    IOctlFlags,
};
use nix::{
    libc::socket,
    sys::socket::{
        self, bind, setsockopt, sockopt, IpMembershipRequest, SockFlag, SockProtocol, SockaddrIn,
    },
};

pub fn open_advertisement_socket(if_name: &str) -> Result<OwnedFd, String> {
    let sock_fd: OwnedFd;

    unsafe {
        // AddressFamily AF_INET 0x02, SocketType SOCK_RAW 0x03, Protocol IPPROTO_VRRPV2 0x70 (112; vrrp)
        sock_fd = match socket(AF_INET, SOCK_RAW, IPPROTO_VRRPV2) {
            -1 => {
                return Err(format!(
                    "Failed to open a raw socket - check the process privileges"
                ));
            }
            fd => OwnedFd::from_raw_fd(fd),
        };
    }

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
            println!("{}", std::io::Error::last_os_error().to_string());
            return Err(format!("Cannot manipulate network interface {}", if_name));
        }
    }

    match setsockopt(&sock_fd, sockopt::ReuseAddr, &true) {
        Ok(_) => {}
        Err(err) => {
            return Err(format!(
                "Error while applying ReuseAddr option for socket {}: {}",
                sock_fd.as_raw_fd().to_string(),
                err
            ));
        }
    }

    match setsockopt(&sock_fd, sockopt::IpMulticastLoop, &false) {
        Ok(_) => {}
        Err(err) => {
            return Err(format!(
                "Error while applying IpMulticastLoop option for socket {}: {}",
                sock_fd.as_raw_fd().to_string(),
                err
            ));
        }
    }

    match setsockopt(&sock_fd, sockopt::IpMulticastTtl, &SOCKET_TTL) {
        Ok(_) => {}
        Err(err) => {
            return Err(format!(
                "Error while applying IPv4TTL option for socket {}: {}",
                sock_fd.as_raw_fd().to_string(),
                err
            ));
        }
    }

    match setsockopt(&sock_fd, sockopt::BindToDevice, &OsString::from(if_name)) {
        Ok(_) => {}
        Err(err) => {
            return Err(format!(
                "Failed to bind advert socket to interface {}: {}",
                if_name,
                err.to_string()
            ));
        }
    }

    let ip_mreq = IpMembershipRequest::new(VRRP_MCAST_ADDR, Some(Ipv4Addr::new(0, 0, 0, 0)));

    match setsockopt(&sock_fd, sockopt::IpAddMembership, &ip_mreq) {
        Ok(_) => {}
        Err(err) => {
            return Err(format!("Error while requesting IP Membership: {}", err));
        }
    }

    match bind(
        sock_fd.as_raw_fd(),
        &SockaddrIn::new(224, 0, 0, 18, IPPROTO_VRRPV2 as u16),
    ) {
        Ok(_) => {}
        Err(err) => {
            return Err(format!("Binding socket failed: {}", err));
        }
    }

    return Ok(sock_fd);
}

pub fn open_arp_socket(if_name: &str) -> Result<OwnedFd, String> {
    // let sock_fd: OwnedFd;

    // unsafe {
    //     // AddressFamily AF_PACKET 0x11, SocketType SOCK_RAW 0x03, Protocol ETH_PROTO_ARP 0x0806 (2054; arp)
    //     // sock_fd = match socket(AF_PACKET, SOCK_RAW, ETH_PROTO_ARP) {
    //     //     -1 => {
    //     //         return Err(format!(
    //     //             "Failed to open a raw socket - check the process privileges"
    //     //         ));
    //     //     }
    //     //     fd => OwnedFd::from_raw_fd(fd),
    //     // };
    // }

    let sock_fd = match nix::sys::socket::socket(
        socket::AddressFamily::Packet,
        socket::SockType::Raw,
        SockFlag::empty(),
        SockProtocol::EthAll,
    ) {
        Ok(fd) => fd,
        Err(err) => {
            return Err(format!(
                "Failed to open a raw socket - check the process privileges {}",
                err.to_string()
            ));
        }
    };

    match setsockopt(&sock_fd, sockopt::Broadcast, &true) {
        Ok(_) => {}
        Err(err) => {
            return Err(format!(
                "Error while setting Broadcast option for socket: {}",
                err
            ));
        }
    };

    match setsockopt(&sock_fd, sockopt::BindToDevice, &OsString::from(if_name)) {
        Ok(_) => {}
        Err(err) => {
            return Err(format!(
                "Failed to bind advert socket to interface {}: {}",
                if_name,
                err.to_string()
            ));
        }
    }

    return Ok(sock_fd);
}
