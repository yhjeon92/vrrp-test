use std::{
    ffi::OsString,
    fmt::Error,
    net::Ipv4Addr,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    process::exit,
};

use std::io;

use bincode::{deserialize, Options};
use core::mem;
use serde::Deserialize;

use nix::{
    errno::Errno,
    ioctl_read,
    libc::{sockaddr, sockaddr_ll},
    sys::socket::{
        bind, recvfrom, setsockopt, socket, sockopt, IpMembershipRequest, SetSockOpt, SockFlag,
        SockProtocol, SockaddrIn,
    },
};

#[repr(C)]
struct ioctl_flags {
    ifr_name: [u8; 16],
    ifr_flags: i16,
}

#[derive(Deserialize, Debug)]
struct VrrpV2Packet {
    // IPv4 Header Fields
    ip_ver: u8,
    ip_dscp: u8,
    ip_length: u16,
    ip_id: u16,
    ip_flags: u16,
    ip_ttl: u8,
    ip_proto: u8,
    ip_checksum: u16,
    ip_src: [u8; 4],
    ip_dst: [u8; 4],

    // VRRPV2 Packet Fields
    ver_type: u8,
    router_id: u8,
    priority: u8,
    cnt_ip_addr: u8,
    auth_type: u8,
    advert_int: u8,
    checksum: u16,
}

fn main() {
    bincode::options().with_big_endian();
    let if_name = "enp3s0";

    let sock_fd = match open_read_socket(&if_name) {
        Ok(fd) => fd,
        Err(err) => {
            println!("[ERROR] {}", err.to_string());
            return;
        }
    };

    println!("Listening for vRRPv2 packets... {}", sock_fd.as_raw_fd());

    let mut pkt_buf: [u8; 1024] = [0; 1024];

    loop {
        // match recvfrom::<SockaddrIn>(sock_fd.as_raw_fd(), &mut pkt_buf) {
        //     Ok((len, from)) => {
        //         pkt_buf[len] = 0;
        //         let message = String::from_utf8_lossy(&pkt_buf);
        //         println!(
        //             "Message of len {} from {}: {}",
        //             len,
        //             match from {
        //                 None => String::new(),
        //                 Some(from_addr) => from_addr.to_string(),
        //             },
        //             message
        //         );

        //         for ind in 0..len {
        //             print!("{} ", pkt_buf[ind]);
        //         }
        //         print!("\n");
        //     }
        //     Err(e) => {
        //         println!("{}", e.to_string())
        //     }
        // };

        // TODO: unsafe
        unsafe {
            let addr_ptr =
                mem::transmute::<*mut nix::libc::sockaddr_ll, *mut sockaddr>(mem::zeroed());
            let mut addr_buf_len: nix::libc::socklen_t =
                mem::size_of::<sockaddr_ll>() as nix::libc::socklen_t;
            let len = match nix::libc::recvfrom(
                sock_fd.as_raw_fd(),
                pkt_buf.as_mut_ptr() as *mut nix::libc::c_void,
                pkt_buf.len(),
                0,
                addr_ptr as *mut sockaddr,
                &mut addr_buf_len,
            ) {
                -1 => {
                    return;
                }
                len => len,
            };

            println!("Message of len {}", len);

            // bincode::deserialize와 bincode::Options::deserialize의 동작이 다르므로 fixint encoding으로 변경함
            let vrrp_pkt: VrrpV2Packet = bincode::DefaultOptions::new()
                .with_fixint_encoding()
                .allow_trailing_bytes()
                .with_big_endian()
                .deserialize(&pkt_buf[0..28])
                .unwrap();

            for ind in 0..len {
                print!("{:02X?} ", pkt_buf[ind as usize]);
            }
            print!("\n");

            println!("IP CHECKSUM {}", vrrp_pkt.ip_checksum);
            println!("CHECKSUM {}", vrrp_pkt.checksum);

            for ind in 0..vrrp_pkt.cnt_ip_addr {}

            verify_ip_checksum(&vrrp_pkt);
            print_vrrpv2_packet(&vrrp_pkt);
        }
    }
}

pub fn open_read_socket(if_name: &str) -> Result<OwnedFd, String> {
    let sock_fd: OwnedFd;

    unsafe {
        // AddressFamily AF_INET, SocketType SOCK_RAW, Protocol 112 (vrrp)
        sock_fd = match nix::libc::socket(0x02, 0x03, 0x70) {
            -1 => {
                return Err(format!(
                    "Failed to open a raw socket - check the process privileges"
                ));
            }
            fd => OwnedFd::from_raw_fd(fd),
        };
        // sock_fd = match socket(
        //     nix::sys::socket::AddressFamily::Inet,
        //     nix::sys::socket::SockType::Raw,
        //     SockFlag::empty(),
        //     SockProtocol::EthAll,
        //     nix::sys::socket::SockProtocol::Vrrp,
        // ) {
        //     Ok(fd) => fd,
        //     Err(err) => {
        //         return Err(format!("Error while opening socket: {}", err.to_string()));
        //     }
        // }
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

    let mut if_opts = ioctl_flags {
        ifr_name: {
            let mut buf = [0u8; 16];
            buf.clone_from_slice(ifname_slice);
            buf
        },
        ifr_flags: 0,
    };

    unsafe {
        // UP (0x01), RUNNING (0x40), MULTICAST (0x1000)
        if_opts.ifr_flags |= 0x1 | 0x40 | 0x1000;
        let res = nix::libc::ioctl(sock_fd.as_raw_fd(), nix::libc::SIOCSIFFLAGS, &mut if_opts);
        if res < 0 {
            println!("{}", io::Error::last_os_error().to_string());
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

    let ip_mreq = IpMembershipRequest::new(
        Ipv4Addr::new(224, 0, 0, 18),
        // None,
        Some(Ipv4Addr::new(0, 0, 0, 0)),
        // Some(Ipv4Addr::new(192, 1, 3, 121)),
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

fn print_vrrpv2_packet(pkt: &VrrpV2Packet) {
    println!("\t{}: {}", "Source", Ipv4Addr::from(pkt.ip_src));
    println!("\t{}: {}", "RouterId", pkt.router_id);
    println!("\t{}: {}", "Priority", pkt.priority);
    println!("\t{}: {}", "AuthType", pkt.auth_type);
    println!("\t{}: {}", "Interval", pkt.advert_int);
}

fn verify_ip_checksum(pkt: &VrrpV2Packet) -> bool {
    let mut sum: u32 = 0;

    sum += u16::from_be_bytes([pkt.ip_ver, pkt.ip_dscp]) as u32;
    sum += pkt.ip_length as u32;
    sum += pkt.ip_id as u32;
    sum += pkt.ip_flags as u32;
    sum += u16::from_be_bytes([pkt.ip_ttl, pkt.ip_proto]) as u32;
    sum += u16::from_be_bytes([pkt.ip_src[0], pkt.ip_src[1]]) as u32;
    sum += u16::from_be_bytes([pkt.ip_src[2], pkt.ip_src[3]]) as u32;
    sum += u16::from_be_bytes([pkt.ip_dst[0], pkt.ip_dst[1]]) as u32;
    sum += u16::from_be_bytes([pkt.ip_dst[2], pkt.ip_dst[3]]) as u32;

    println!("CHECKSUM {:05X?}", sum);

    sum += pkt.ip_checksum as u32;

    println!("VERIFYING CHECKSUM {:05X?}", sum);

    return true;
}
