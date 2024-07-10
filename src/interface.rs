use std::{
    ffi::c_void,
    io::IoSlice,
    net::Ipv4Addr,
    os::fd::{AsRawFd, OwnedFd},
};

use nix::{
    ioctl_write_ptr,
    libc::{in_addr, msghdr, sockaddr, sockaddr_in, sockaddr_nl},
    sys::socket::{sendmsg, ControlMessage, LinkAddr, MsgFlags, SockaddrIn},
};

use crate::{
    constants::{AF_INET, IFR_FLAG_MULTICAST, IFR_FLAG_RUNNING, IFR_FLAG_UP},
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

    // let msg_name = nix::sys::socket::NetlinkAddr::new(0, 0);

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
