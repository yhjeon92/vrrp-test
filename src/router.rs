use std::{
    net::Ipv4Addr,
    os::fd::{AsRawFd, OwnedFd},
    sync::Arc,
    thread,
};

use arc_swap::{access::Access, ArcSwap};
use nix::sys::socket::{MsgFlags, SockaddrIn};
use once_cell::sync::Lazy;

use crate::{VrrpV2Packet, ADVERT, CONFIG};

static MULTICAST: Lazy<ArcSwap<bool>> = Lazy::new(|| ArcSwap::from_pointee(true));

pub struct Router {
    sock_fd: OwnedFd,
    router_id: u8,
    priority: u8,
    advert_int: u8,
    virtual_ip: Ipv4Addr,
}

impl Router {
    pub fn new(fd: OwnedFd) -> Router {
        let config = CONFIG.load_full();
        Router {
            sock_fd: fd,
            router_id: config.router_id,
            priority: config.priority,
            advert_int: config.advert_int,
            virtual_ip: config.virtual_ip,
        }
    }

    pub fn start(&self) {
        println!("Router thread running...");

        let cloned_fd = self.sock_fd.as_raw_fd().clone();

        let advert_pkt = match self.build_packet() {
            Some(pkt) => pkt,
            _ => {
                println!("[ERROR] failed to build VRRP advertisement packet");
                return;
            }
        };

        let cloned_advert_int = self.advert_int.clone();

        thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_secs(cloned_advert_int as u64));
            if *MULTICAST.load_full() {
                send_advertisement(cloned_fd, advert_pkt.clone());
            };
        });

        // main router loop
        // TODO: Separate listening & advertising into different threads
        loop {
            // Check
            let advert = ADVERT.load_full();
            if advert.0 && advert.1.router_id == self.router_id {
                println!("Router received VRRPv2 advertisement!");
                println!("\tSource {}", Ipv4Addr::from(advert.1.ip_src));
                println!("\tRouter Id {}", advert.1.router_id);
                println!("\tPriority {}", advert.1.priority);
                ADVERT.store(Arc::new((false, VrrpV2Packet::new())));
                MULTICAST.store(Arc::new(!*MULTICAST.load_full()));
            }
            std::thread::sleep(std::time::Duration::from_millis(100 as u64));

            // self.send_advertisement();
        }
    }

    fn build_packet(&self) -> Option<Vec<u8>> {
        let mut pkt_hdr = VrrpV2Packet::new();
        pkt_hdr.router_id = self.router_id;
        pkt_hdr.priority = self.priority;
        pkt_hdr.cnt_ip_addr = 1;
        pkt_hdr.auth_type = 1;
        pkt_hdr.advert_int = self.advert_int;

        let mut vip_addresses: Vec<Ipv4Addr> = Vec::new();
        vip_addresses.push(self.virtual_ip);

        pkt_hdr.set_vip_addresses(&vip_addresses);

        let auth_data = [49, 49, 49, 49, 0, 0, 0, 0].to_vec();

        pkt_hdr.set_auth_data(&auth_data);

        Some(pkt_hdr.to_bytes())
    }
}

pub fn send_advertisement(sock_fd: i32, pkt_vec: Vec<u8>) {
    match nix::sys::socket::sendto(
        sock_fd.as_raw_fd(),
        &pkt_vec.as_slice(),
        &SockaddrIn::new(224, 0, 0, 18, 112),
        MsgFlags::empty(),
    ) {
        Ok(size) => {
            println!("A VRRPV2 packet was sent! {}", size);
        }
        Err(err) => {
            println!(
                "An error was encountered while sending packet! {}",
                err.to_string()
            );
        }
    }
}
