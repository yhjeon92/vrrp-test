use std::{
    net::Ipv4Addr,
    os::fd::{AsRawFd, OwnedFd},
    sync::Arc,
};

use nix::sys::socket::{MsgFlags, SockaddrIn};

use crate::{VrrpV2Packet, ADVERT, CONFIG};

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
        // main router loop
        // TODO: Separate listening & advertising into different threads
        loop {
            let advert = ADVERT.load_full();
            if advert.0 {
                println!("Router received VRRPv2 advertisement!");
                println!("\tSource {}", Ipv4Addr::from(advert.1.ip_src));
                println!("\tRouter Id {}", advert.1.router_id);
                println!("\tPriority {}", advert.1.priority);
                ADVERT.store(Arc::new((false, VrrpV2Packet::new())));
            }
            std::thread::sleep(std::time::Duration::from_secs(self.advert_int as u64));
            self.send_advertisement();
        }
    }

    fn send_advertisement(&self) {
        match self.build_packet() {
            Some(pkt_vec) => {
                match nix::sys::socket::sendto(
                    self.sock_fd.as_raw_fd(),
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
            _ => {
                println!("[ERROR] Failed to send vrrpv2 advertisement");
            }
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

        let auth_data: [u8; 8] = [49, 49, 49, 49, 0, 0, 0, 0];

        Some(pkt_hdr.to_bytes(&vip_addresses, &auth_data))
    }
}
