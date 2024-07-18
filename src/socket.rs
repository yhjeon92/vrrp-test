use std::{
    convert::TryInto,
    ffi::OsString,
    net::Ipv4Addr,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

use crate::{
    constants::{
        AF_INET, AF_PACKET, ETH_PROTO_ARP, IPPROTO_IP, IPPROTO_VRRPV2, SOCKET_TTL, SOCK_DGRAM,
        SOCK_RAW, VRRP_HDR_LEN, VRRP_MCAST_ADDR,
    },
    interface::{get_if_index, set_if_multicast_flag},
    packet::{GarpPacket, VrrpV2Packet},
};
use bincode::Options;
use log::{debug, error, info, warn};
use nix::{
    libc::{sockaddr, sockaddr_ll, socket},
    sys::socket::{
        self, bind, recvfrom, setsockopt, sockopt, IpMembershipRequest, LinkAddr, MsgFlags,
        SockFlag, SockProtocol, SockaddrIn, SockaddrLike,
    },
};

pub fn open_ip_socket() -> Result<OwnedFd, String> {
    let sock_fd: OwnedFd;

    unsafe {
        sock_fd = match socket(AF_INET, SOCK_DGRAM, IPPROTO_IP) {
            -1 => {
                return Err(format!(
                    "Failed to open a socket - check the process privileges"
                ));
            }
            fd => OwnedFd::from_raw_fd(fd),
        };
    }

    Ok(sock_fd)
}

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

    match set_if_multicast_flag(&sock_fd, if_name) {
        Ok(_) => {}
        Err(err) => {
            return Err(err);
        }
    }

    // SOL_SOCKET, SO_REUSEADDR
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

    // IPPROTO_IP, IP_MULTICAST_LOOP
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

    // IPPROTO_IP, IP_MULTICAST_TTL
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

    // SOL_SOCKET, SO_BINDTODEVICE
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

    // IPPROTO_IP, IP_ADD_MEMBERSHIP
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

    // SOL_SOCKET, SO_BROADCAST
    match setsockopt(&sock_fd, sockopt::Broadcast, &true) {
        Ok(_) => {}
        Err(err) => {
            return Err(format!(
                "Error while setting Broadcast option for socket: {}",
                err
            ));
        }
    };

    // SOL_SOCKET, SO_BINDTODEVICE
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

pub fn open_netlink_socket() -> Result<OwnedFd, String> {
    let sock_fd = match nix::sys::socket::socket(
        socket::AddressFamily::Netlink,
        socket::SockType::Raw,
        SockFlag::SOCK_CLOEXEC,
        SockProtocol::NetlinkRoute,
    ) {
        Ok(fd) => fd,
        Err(err) => {
            return Err(format!(
                "Failed to open a raw socket - check the process privileges {}",
                err.to_string()
            ));
        }
    };

    // socketFd - level - name - value - option_len
    match setsockopt(&sock_fd, sockopt::SndBuf, &32768) {
        Ok(_) => {}
        Err(err) => {
            return Err(format!(
                "Error while setting SndBuf option for socket: {}",
                err
            ));
        }
    };

    match setsockopt(&sock_fd, sockopt::RcvBuf, &1048576) {
        Ok(_) => {}
        Err(err) => {
            return Err(format!(
                "Error while setting RcvBuf option for socket: {}",
                err
            ));
        }
    };

    let sock_addr = nix::sys::socket::NetlinkAddr::new(0, 0);

    match bind(sock_fd.as_raw_fd(), &sock_addr) {
        Ok(_) => {}
        Err(err) => {
            return Err(format!("Error while binding Netlink socket: {}", err));
        }
    };

    Ok(sock_fd)
}

pub fn send_gratuitous_arp(
    sock_fd: i32,
    if_name: String,
    router_id: u8,
    virtual_ip: (Ipv4Addr, u8),
) {
    let mut pkt = GarpPacket::new(virtual_ip.0, router_id);

    let if_index = match get_if_index(&if_name) {
        Ok(ind) => ind,
        Err(err) => {
            error!("{}", err);
            return;
        }
    };

    debug!("interface {} index {}", if_name, if_index);

    unsafe {
        let mut sock_addr = nix::libc::sockaddr_ll {
            sll_family: AF_PACKET as u16,
            sll_protocol: ETH_PROTO_ARP as u16,
            sll_ifindex: if_index as i32,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };

        let ptr_sockaddr = core::mem::transmute::<*mut sockaddr_ll, *mut sockaddr>(&mut sock_addr);

        let sock_addr = match LinkAddr::from_raw(ptr_sockaddr, None) {
            Some(addr) => addr,
            None => {
                error!("Failed to construct sockaddr");
                return;
            }
        };

        match nix::sys::socket::sendto(
            sock_fd.as_raw_fd(),
            &pkt.to_bytes().as_slice(),
            &sock_addr,
            MsgFlags::empty(),
        ) {
            Ok(size) => {
                info!("Sent a GARP of len {}", size);
            }
            Err(err) => {
                warn!(
                    "An error was encountered while sending GARP request! {}",
                    err.to_string()
                );
            }
        }
    }
}

pub fn recv_vrrp_packet(sock_fd: &OwnedFd, pkt_buf: &mut [u8]) -> Result<VrrpV2Packet, String> {
    let len = match recvfrom::<SockaddrIn>(sock_fd.as_raw_fd(), pkt_buf) {
        Ok((pkt_len, _)) => pkt_len,
        Err(err) => {
            return Err(format!("recvfrom() error: {}", err.to_string()));
        }
    };

    // bincode::deserialize와 bincode::Options::deserialize의 동작이 다르므로 fixint encoding으로 변경함
    let mut vrrp_pkt: VrrpV2Packet = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_big_endian()
        .deserialize(&pkt_buf[0..VRRP_HDR_LEN])
        .unwrap();

    debug!("VRRPv2 socket received a packet:");
    debug!(
        "{}",
        pkt_buf[0..len]
            .iter()
            .map(|byte| format!("{:02X?} ", byte))
            .collect::<String>()
    );

    let mut vip_addresses: Vec<Ipv4Addr> = Vec::new();

    for ind in 0..vrrp_pkt.cnt_ip_addr {
        vip_addresses.push(Ipv4Addr::from(u32::from_be_bytes(
            pkt_buf[VRRP_HDR_LEN + (ind * 4) as usize..VRRP_HDR_LEN + 4 + (ind * 4) as usize]
                .try_into()
                .unwrap(),
        )));
    }

    vrrp_pkt.set_vip_addresses(&vip_addresses);

    let auth_data =
        pkt_buf[VRRP_HDR_LEN + (vrrp_pkt.cnt_ip_addr * 4) as usize..len as usize].to_vec();

    vrrp_pkt.set_auth_data(&auth_data);

    return Ok(vrrp_pkt);
}
