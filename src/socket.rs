use std::{
    net::Ipv4Addr,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

use crate::{
    constants::{
        AF_INET, AF_PACKET, ETH_PROTO_ARP, IFR_FLAG_MULTICAST, IFR_FLAG_RUNNING, IFR_FLAG_UP,
        IPPROTO_VRRPV2, SOCKET_TTL, SOCK_RAW,
    },
    IOctlFlags,
};
use nix::{
    libc::socket,
    sys::socket::{bind, setsockopt, sockopt, IpMembershipRequest, SockaddrIn},
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

    // if_nametoindex는 1-인덱싱, iter().nth()는 0-인덱싱
    let if_ind = match nix::net::if_::if_nametoindex(if_name) {
        Ok(ind) => ind - 1,
        Err(_) => {
            return Err(format!("No interface named {}", if_name));
        }
    };

    let interfaces = nix::net::if_::if_nameindex().unwrap();
    let interface = interfaces.iter().nth(if_ind as usize).unwrap();

    let ifname_slice = &mut [0u8; 16];

    for (i, b) in interface.name().to_bytes().iter().enumerate() {
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
            return Err(format!(
                "Cannot manipulate network interface {}",
                interface.name().to_string_lossy()
            ));
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

    let ip_mreq = IpMembershipRequest::new(
        Ipv4Addr::new(224, 0, 0, 18),
        Some(Ipv4Addr::new(0, 0, 0, 0)),
    );

    match setsockopt(&sock_fd, sockopt::IpAddMembership, &ip_mreq) {
        Ok(_) => {}
        Err(err) => {
            return Err(format!("Error while requesting IP Membership: {}", err));
        }
    }

    match bind(sock_fd.as_raw_fd(), &SockaddrIn::new(224, 0, 0, 18, 112)) {
        Ok(_) => {}
        Err(err) => {
            return Err(format!("Binding socket failed: {}", err));
        }
    }

    return Ok(sock_fd);
}

pub fn open_arp_socket() -> Result<OwnedFd, String> {
    let sock_fd: OwnedFd;

    unsafe {
        // AddressFamily AF_PACKET 0x11, SocketType SOCK_RAW 0x03, Protocol ETH_PROTO_ARP 0x0806 (2054; arp)
        sock_fd = match socket(AF_PACKET, SOCK_RAW, ETH_PROTO_ARP) {
            -1 => {
                return Err(format!(
                    "Failed to open a raw socket - check the process privileges"
                ));
            }
            fd => OwnedFd::from_raw_fd(fd),
        };
    }

    return Ok(sock_fd);
}
