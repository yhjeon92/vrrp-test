use std::{fs::File, io::Read, mem::size_of, net::Ipv4Addr, thread, time::Duration};

use interface::get_ip_address;
use log::{debug, error, info, warn};
use packet::VrrpV2Packet;
use router::{Event, Router};
use serde::{Deserialize, Serialize};
use socket::{open_advertisement_socket, open_arp_socket, recv_vrrp_packet};
use tokio::sync::mpsc::{self, Receiver};

mod constants;
mod interface;
mod packet;
mod router;
mod socket;

#[derive(Serialize, Deserialize)]
pub struct VRouterConfig {
    pub interface: String,
    pub router_id: u8,
    pub priority: u8,
    pub advert_int: u8,
    pub virtual_ip: Ipv4Addr,
    pub netmask_len: u8,
}

impl VRouterConfig {
    pub fn from_file(path: &str) -> Option<VRouterConfig> {
        let mut contents = String::new();
        let mut file_handle = match File::open(path) {
            Ok(file) => file,
            Err(err) => {
                error!(
                    "Failed to open configuration file {}: {}",
                    path,
                    err.to_string()
                );
                return None;
            }
        };

        match file_handle.read_to_string(&mut contents) {
            Ok(_) => {}
            Err(err) => {
                error!(
                    "Failed to read configuration file {}: {}",
                    path,
                    err.to_string()
                );
                return None;
            }
        }

        match toml::from_str::<VRouterConfig>(&contents) {
            Ok(config) => {
                if config.netmask_len < 8 || config.netmask_len > 31 {
                    error!("Invalid virtual ip netmask length {}", config.netmask_len);
                    return None;
                }
                info!("Router configured:");
                info!("\tInterface       {}", config.interface);
                info!("\tRouter ID       {}", config.router_id);
                info!("\tPriority        {}", config.priority);
                info!("\tAdvert Interval {}s", config.advert_int);
                info!(
                    "\tVirtual IP      {}/{}",
                    config.virtual_ip.to_string(),
                    config.netmask_len
                );
                Some(config)
            }
            Err(err) => {
                error!(
                    "Failed to parse configuration from given file {}: {}",
                    path,
                    err.to_string()
                );
                None
            }
        }
    }
}

fn read_config(file_path: &str) -> Option<VRouterConfig> {
    match VRouterConfig::from_file(file_path) {
        Some(config) => Some(config),
        None => {
            error!("Failed to construct a valid configuration settings. Exiting...");
            None
        }
    }
}

pub async fn start_vrouter_async(config: VRouterConfig, mut shutdown_rx: Receiver<()>) {
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

    tokio::task::spawn(async move { router.start().await });
    // tokio::spawn(async move { router.start().await });

    // tokio::spawn(async move {
    //     match shutdown_rx.blocking_recv().recv().await {
    //         Ok(_) => {
    //             _ = router_tx_cloned.clone().send(Event::_ShutDown).await;
    //             return;
    //         }
    //         Err(_) => {
    //             return;
    //         }
    //     }
    // });

    let tx_handle = tx.clone();

    tokio::task::spawn(async move {
        match shutdown_rx.recv().await {
            Some(()) => {
                _ = tx_handle.clone().send(Event::_ShutDown).await;
            }
            None => {}
        }
    });

    _ = tx.send(Event::Startup).await;

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
                match tx
                    .send(Event::AdvertReceived(
                        router_id,
                        priority,
                        Ipv4Addr::from(src_addr),
                    ))
                    .await
                {
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

pub async fn start_vrouter_cfile_async(config_file_path: String, shutdown_rx: Receiver<()>) {
    let config = match read_config(&config_file_path) {
        Some(config) => config,
        None => {
            return;
        }
    };

    start_vrouter_async(config, shutdown_rx).await;
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

pub fn debugger(if_name: &str) {
    match get_ip_address(if_name) {
        Ok(_addr) => {}
        Err(err) => {
            error!("{}", err);
        }
    }
}
