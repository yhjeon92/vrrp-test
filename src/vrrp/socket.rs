use std::{
    ffi::OsString,
    net::Ipv4Addr,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

use crate::vrrp::{
    constants::{
        AF_INET, AF_PACKET, BROADCAST_MAC_SOCKADDR_LL, ETH_PROTO_ARP, IPPROTO_IP, IPPROTO_VRRPV2,
        SOCKET_TTL, SOCK_CLOEXEC, SOCK_DGRAM, SOCK_RAW, VRRP_MCAST_ADDR,
    },
    interface::{get_if_index, get_mac_address, set_if_multicast_flag},
    packet::{GarpPacket, VrrpV2Packet},
    Ipv4WithNetmask,
};
use itertools::Itertools;
use log::debug;
use nix::{
    libc::{sockaddr, sockaddr_ll, socket},
    sys::socket::{
        self, bind, recvfrom, setsockopt, sockopt, IpMembershipRequest, LinkAddr, MsgFlags,
        SockFlag, SockProtocol, SockaddrIn, SockaddrLike,
    },
};

use super::interface::get_ip_address;

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

pub fn open_advertisement_socket(if_name: &str, multicast: bool) -> Result<OwnedFd, String> {
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

    if multicast {
        match set_if_multicast_flag(&sock_fd, if_name) {
            Ok(_) => {}
            Err(err) => {
                return Err(err);
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

        let ip_mreq = IpMembershipRequest::new(
            VRRP_MCAST_ADDR,
            Some(match get_ip_address(if_name) {
                Ok(addr) => addr,
                Err(err) => {
                    return Err(format!("Failed to join multicast group: {}", err));
                }
            }),
        );

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
    } else {
        match setsockopt(&sock_fd, sockopt::Ipv4Ttl, &(SOCKET_TTL as i32)) {
            Ok(_) => {}
            Err(err) => {
                return Err(format!(
                    "Error while applying IPv4TTL option for socket {}: {}",
                    sock_fd.as_raw_fd().to_string(),
                    err
                ));
            }
        }

        let local_addr = match get_ip_address(if_name) {
            Ok(addr) => addr,
            Err(err) => {
                return Err(format!("Failed to fetch local net address: {}", err));
            }
        };

        match bind(
            sock_fd.as_raw_fd(),
            &SockaddrIn::new(
                local_addr.octets()[0],
                local_addr.octets()[1],
                local_addr.octets()[2],
                local_addr.octets()[3],
                IPPROTO_VRRPV2 as u16,
            ),
        ) {
            Ok(_) => {}
            Err(err) => {
                return Err(format!("Binding socket failed: {}", err));
            }
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

    return Ok(sock_fd);
}

pub fn open_arp_socket(if_name: &str) -> Result<OwnedFd, String> {
    let sock_fd: OwnedFd;

    unsafe {
        sock_fd = match socket(
            AF_PACKET,
            SOCK_RAW | SOCK_CLOEXEC,
            (ETH_PROTO_ARP.to_be()) as i32,
        ) {
            -1 => {
                return Err(format!(
                    "Failed to open a raw socket - check the process privileges"
                ));
            }
            fd => OwnedFd::from_raw_fd(fd),
        };
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

pub fn send_advertisement(sock_fd: i32, mut vrrp_pkt: VrrpV2Packet) -> Result<(), String> {
    match nix::sys::socket::sendto(
        sock_fd.as_raw_fd(),
        &vrrp_pkt.to_bytes().as_slice(),
        &SockaddrIn::new(224, 0, 0, 18, 112),
        MsgFlags::empty(),
    ) {
        Ok(_) => Ok(()),
        Err(err) => Err(format!("Multicasting advert failed: {}", err.to_string())),
    }
}

pub fn send_advertisement_unicast(
    sock_fd: i32,
    mut vrrp_pkt: VrrpV2Packet,
    peers: Vec<Ipv4Addr>,
) -> Result<(), String> {
    for peer in peers {
        let peer_addr_octet = peer.octets();
        vrrp_pkt.ip_dst = peer_addr_octet.clone();
        match nix::sys::socket::sendto(
            sock_fd.as_raw_fd(),
            &vrrp_pkt.to_bytes().as_slice(),
            &SockaddrIn::new(
                peer_addr_octet[0],
                peer_addr_octet[1],
                peer_addr_octet[2],
                peer_addr_octet[3],
                112,
            ),
            MsgFlags::empty(),
        ) {
            Ok(_) => {}
            Err(err) => {
                return Err(format!(
                    "Sending advert to {} failed: {}",
                    peer,
                    err.to_string()
                ))
            }
        }
    }

    Ok(())
}

pub fn send_gratuitous_arp(
    sock_fd: i32,
    if_name: &str,
    _router_id: u8,
    virtual_ip: &Ipv4WithNetmask,
) -> Result<(), String> {
    let local_hw_addr = match get_mac_address(&if_name) {
        Ok(hw_addr) => hw_addr,
        Err(err) => {
            return Err(format!(
                "Failed to fetch local hardware address: {}",
                err.to_string()
            ));
        }
    };

    let mut pkt = GarpPacket::new(virtual_ip.address, local_hw_addr);

    let if_index = match get_if_index(&if_name) {
        Ok(ind) => ind,
        Err(err) => return Err(format!("Cannot find interface named {}: {}", &if_name, err)),
    };

    debug!("interface {} index {}", if_name, if_index);

    unsafe {
        let mut sock_addr = nix::libc::sockaddr_ll {
            sll_family: AF_PACKET as u16,
            sll_protocol: ETH_PROTO_ARP.to_be(),
            sll_ifindex: if_index as i32,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 6,
            sll_addr: BROADCAST_MAC_SOCKADDR_LL,
        };

        let ptr_sockaddr = core::mem::transmute::<*mut sockaddr_ll, *mut sockaddr>(&mut sock_addr);

        let sock_addr = match LinkAddr::from_raw(ptr_sockaddr, None) {
            Some(addr) => addr,
            None => {
                return Err(format!(
                    "Failed to initialize sockaddr: {}",
                    std::io::Error::last_os_error().to_string()
                ));
            }
        };

        match nix::sys::socket::sendto(
            sock_fd.as_raw_fd(),
            &pkt.to_bytes().as_slice(),
            &sock_addr,
            MsgFlags::empty(),
        ) {
            Ok(size) => {
                debug!(
                    "Broadcasted gratuitious ARP for {}: len {}",
                    virtual_ip.address, size
                );
                Ok(())
            }
            Err(err) => Err(format!(
                "An error was encountered while sending GARP request: {}",
                err.to_string()
            )),
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

    let vrrp_pkt = match VrrpV2Packet::from_slice(&pkt_buf[0..len]) {
        Some(pkt) => pkt,
        None => {
            return Err("failed to deserialize VRRPv2 advert packet".to_string());
        }
    };

    debug!(
        "Received a VRRPv2 packet: RouterID [{}] Priority [{}] VIPs [{}] Advert Int [{}] SRC [{}]",
        vrrp_pkt.router_id,
        vrrp_pkt.priority,
        vrrp_pkt
            .vip_addresses
            .iter()
            .map(|address| format!("{}", address.to_string()))
            .join(", "),
        vrrp_pkt.advert_int,
        vrrp_pkt
            .ip_src
            .iter()
            .map(|byte| format!("{}", byte))
            .join(".")
    );

    return Ok(vrrp_pkt);
}
