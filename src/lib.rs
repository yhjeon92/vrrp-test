use std::{mem::size_of, net::Ipv4Addr, thread};

use config::VRouterConfig;
use log::{error, info, warn};
use packet::VrrpV2Packet;
use router::{Event, Router};
use socket::{open_advertisement_socket, open_arp_socket, recv_vrrp_packet};
use tokio::sync::mpsc;

mod config;
mod constants;
mod interface;
mod packet;
mod router;
mod socket;

fn read_config(file_path: &str) -> Option<VRouterConfig> {
    match VRouterConfig::from_file(file_path) {
        Some(config) => Some(config),
        None => {
            info!("Failed to construct a valid configuration settings. Exiting...");
            None
        }
    }
}

pub fn start_virtual_router(config: VRouterConfig) {
    let if_name = config.interface.clone();
    let vrrp_sock_fd = match open_advertisement_socket(&if_name) {
        Ok(fd) => fd,
        Err(err) => {
            error!("Failed to open a socket: {}, exiting...", err.to_string());
            return;
        }
    };

    let mut pkt_buf: [u8; 1024] = [0u8; 1024];

    let (tx, rx) = mpsc::channel::<Event>(size_of::<Event>());

    let arp_sock_fd = match open_arp_socket(&if_name) {
        Ok(fd) => fd,
        Err(err) => {
            error!(
                "Failed to open an arp socket: {}, exiting...",
                err.to_string()
            );
            return;
        }
    };

    let mut router = match Router::new(
        if_name,
        match vrrp_sock_fd.try_clone() {
            Ok(fd) => fd,
            Err(err) => {
                error!("Failed to clone socket fd: {}, exiting...", err.to_string());
                return;
            }
        },
        arp_sock_fd,
        tx.clone(),
        rx,
        config,
    ) {
        Ok(router) => router,
        Err(err) => {
            error!(
                "Failed to initialize a router: {}, exiting...",
                err.to_string()
            );
            return;
        }
    };

    thread::spawn(move || router.start());

    _ = tx.blocking_send(Event::Startup);

    info!("Router Startup");
    info!("Listening for vRRPv2 packets...");

    // Main Loop
    loop {
        let vrrp_pkt: VrrpV2Packet = match recv_vrrp_packet(&vrrp_sock_fd, &mut pkt_buf) {
            Ok(pkt) => pkt,
            Err(err) => {
                error!("{}", err.to_string());
                continue;
            }
        };

        let router_id = vrrp_pkt.router_id;
        let priority = vrrp_pkt.priority;
        let src_addr = vrrp_pkt.ip_src.clone();

        match vrrp_pkt.verify_checksum() {
            Ok(_) => {
                match tx.blocking_send(Event::AdvertReceived(
                    router_id,
                    priority,
                    Ipv4Addr::from(src_addr),
                )) {
                    Ok(()) => {}
                    Err(err) => {
                        error!("Failed to send event: {}", err.to_string());
                    }
                }
            }
            Err(err) => {
                warn!("Invalid VRRP packet received: {}", err);
            }
        }
    }
}

pub fn start_virutal_router(config_file_path: &str) {
    let config = match read_config(config_file_path) {
        Some(config) => config,
        None => {
            return;
        }
    };

    start_virtual_router(config);
}

pub fn start_vrrp_listener(if_name: String) {
    let vrrp_sock_fd = match open_advertisement_socket(&if_name) {
        Ok(fd) => fd,
        Err(err) => {
            error!("Failed to open a socket: {}, exiting...", err.to_string());
            return;
        }
    };

    let mut pkt_buf: [u8; 1024] = [0u8; 1024];

    info!("Listening for vRRPv2 packets...");

    // Listener Main Loop
    loop {
        let vrrp_pkt: VrrpV2Packet = match recv_vrrp_packet(&vrrp_sock_fd, &mut pkt_buf) {
            Ok(pkt) => pkt,
            Err(err) => {
                error!("{}", err.to_string());
                continue;
            }
        };

        let router_id = vrrp_pkt.router_id;
        let priority = vrrp_pkt.priority;
        let src_addr = vrrp_pkt.ip_src.clone();

        info!(
            "VRRPv2 advertisement received: router id {} - prior {} - src {}.{}.{}.{}",
            router_id, priority, src_addr[0], src_addr[1], src_addr[2], src_addr[3]
        );

        match vrrp_pkt.verify_checksum() {
            Ok(_) => {
                vrrp_pkt.print();
            }
            Err(err) => {
                warn!("Invalid VRRP packet received: {}", err);
            }
        }
    }
}
