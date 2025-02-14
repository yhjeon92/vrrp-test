mod constants;
mod interface;
mod packet;
mod router;
mod socket;

use core::fmt;
use std::{fs::File, io::Read, net::Ipv4Addr, os::fd::AsRawFd, str::FromStr};

use log::{debug, error, info, warn};
use packet::VrrpV2Packet;
use router::{Event, Router};
use serde::{
    de::Error,
    {Deserialize, Serialize},
};
use socket::{open_advertisement_socket, open_arp_socket, recv_vrrp_packet};
use tokio::sync::mpsc::{self, Receiver};

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct Ipv4WithNetmask {
    pub address: Ipv4Addr,
    pub netmask: u8,
}

impl fmt::Display for Ipv4WithNetmask {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.netmask)
    }
}

impl<'de> serde::de::Deserialize<'de> for Ipv4WithNetmask {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let masked_address = String::deserialize(deserializer)?;

        if !masked_address.contains("/") {
            return Err(D::Error::custom(format!(
                "Invalid address {}: must include netmask length",
                masked_address
            )));
        }

        let data_vec: Vec<&str> = masked_address.split("/").collect();

        if data_vec.len() != 2 {
            return Err(D::Error::custom(format!(
                "Invalid address {}: must include netmask length",
                masked_address
            )));
        }

        Ok(Ipv4WithNetmask {
            address: match Ipv4Addr::from_str(data_vec[0]) {
                Ok(addr) => addr,
                Err(err) => {
                    return Err(D::Error::custom(err.to_string()));
                }
            },
            netmask: match u8::from_str(data_vec[1]) {
                Ok(mask) => mask,
                Err(err) => {
                    return Err(D::Error::custom(err.to_string()));
                }
            },
        })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct VRouterConfig {
    pub interface: String,
    pub router_id: u8,
    pub priority: u8,
    pub advert_int: u8,
    pub vip_addresses: Vec<Ipv4WithNetmask>,
    pub pre_promote_script: Option<String>,
    pub pre_demote_script: Option<String>,
    pub unicast_peers: Option<Vec<Ipv4Addr>>,
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
            Ok(mut config) => {
                if config.vip_addresses.len() < 1 {
                    error!("No virtual ip is configured");
                    return None;
                }

                for virtual_ip in config.vip_addresses.iter() {
                    if virtual_ip.netmask < 8 || virtual_ip.netmask > 31 {
                        error!("Invalid virtual ip netmask length {}", virtual_ip.netmask);
                        return None;
                    }
                }

                if config.advert_int == 0 {
                    warn!("VRRP advertisement interval must be at least 1 second");
                    config.advert_int = 1;
                }

                info!("Router configured:");
                info!("\tInterface       {}", config.interface);
                info!("\tRouter ID       {}", config.router_id);
                info!("\tPriority        {}", config.priority);
                info!("\tAdvert Interval {}s", config.advert_int);

                info!("\tVIP addresses");

                for virtual_ip in config.vip_addresses.iter() {
                    info!("\t\t- {}/{}", virtual_ip.address, virtual_ip.netmask);
                }

                match config.pre_promote_script {
                    Some(ref script) => {
                        info!("\tPre-promotion script       {}", script);
                    }
                    _ => {}
                }

                match config.pre_demote_script {
                    Some(ref script) => {
                        info!("\tPre-demotion script       {}", script);
                    }
                    _ => {}
                }

                match config.unicast_peers {
                    Some(ref peers) => {
                        info!("\tUnicast peers:");
                        for peer in peers {
                            info!("\t\t- {}", peer)
                        }
                    }
                    _ => {}
                }

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

pub async fn start_vrouter(config: VRouterConfig, mut shutdown_rx: Receiver<()>) {
    let if_name = config.interface.clone();
    let vrrp_sock_fd = match open_advertisement_socket(
        &if_name,
        match config.unicast_peers {
            Some(_) => false,
            None => true,
        },
    ) {
        Ok(fd) => fd,
        Err(err) => {
            error!("Failed to open a socket: {}, exiting...", err.to_string());
            return;
        }
    };

    let (tx, rx) = mpsc::channel::<Event>(3);

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
        config.clone(),
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

    tokio::spawn(async move { router.start().await });

    let tx_handle = tx.clone();

    match tx.send(Event::Startup).await {
        Ok(()) => {
            // do nothing
        }
        Err(err) => {
            error!("TEST_LOG: {}", err.to_string());
            return;
        }
    }

    info!("Router Startup");
    info!("Listening for vRRPv2 packets...");

    let mut pkt_buf: [u8; 1024] = [0u8; 1024];

    let vrrp_sock_fd_cloned = match vrrp_sock_fd.try_clone() {
        Ok(fd) => fd,
        Err(err) => {
            error!("Failed to clone socket fd: {}, exiting...", err.to_string());
            return;
        }
    };

    tokio::task::spawn_blocking(move || {
        loop {
            match recv_vrrp_packet(&vrrp_sock_fd_cloned, &mut pkt_buf) {
                Ok(vrrp_pkt) => {
                    let router_id = vrrp_pkt.router_id;
                    let priority = vrrp_pkt.priority;
                    let src_addr = vrrp_pkt.ip_src.clone();

                    match vrrp_pkt.verify() {
                        Ok(_) => {
                            /* additional packet validation using local VRouter config */
                            if vrrp_pkt.router_id != config.router_id {
                                debug!(
                                    "Mismatching router id of received packet {} - local router id is configured to {}, discarding packet..",
                                    vrrp_pkt.router_id,
                                    config.router_id
                                );

                                continue;
                            }

                            if vrrp_pkt.advert_int != config.advert_int {
                                debug!(
                                    "Mismatching advert interval of received packet {}s - local advert interval is configured to {}s, discarding packet..",
                                    vrrp_pkt.advert_int,
                                    config.advert_int
                                );

                                continue;
                            }

                            match tx.blocking_send(Event::AdvertReceived(
                                router_id,
                                priority,
                                Ipv4Addr::from(src_addr),
                                vrrp_pkt.vip_addresses,
                            )) {
                                Ok(()) => {}
                                Err(err) => {
                                    error!("Failed to send event: {}, exiting...", err.to_string());
                                    return;
                                }
                            }
                        }
                        Err(err) => {
                            warn!("Invalid VRRP packet received: {}", err);
                        }
                    }
                }
                Err(err) => {
                    warn!("Reading VRRP packet failed: {}", err);
                    break;
                }
            }
        }
    });

    loop {
        match shutdown_rx.recv().await {
            Some(()) => {
                debug!("Stopping a router thread");
                match tx_handle.clone().send(Event::ShutDown).await {
                    Ok(()) => match tx_handle.clone().send(Event::ShutDown).await {
                        Ok(()) => {
                            debug!("Succees");
                        }
                        Err(err) => {
                            debug!("Error: {}", err.to_string());
                        }
                    },
                    Err(err) => {
                        debug!("Error: {}", err.to_string());
                    }
                }
                debug!("Stopping a packet receiver");
                match nix::sys::socket::shutdown(
                    vrrp_sock_fd.as_raw_fd(),
                    nix::sys::socket::Shutdown::Both,
                ) {
                    Ok(()) => {
                        debug!("socket dropped");
                    }
                    Err(err) => {
                        warn!(
                            "Failed to drop an advert listening socket: {}",
                            err.to_string()
                        );
                    }
                }
                break;
            }
            None => {}
        }
    }

    info!("virtual router terminated");
}

pub async fn start_vrouter_cfile(config_file_path: String, shutdown_rx: Receiver<()>) {
    let config = match read_config(&config_file_path) {
        Some(config) => config,
        None => {
            return;
        }
    };

    start_vrouter(config, shutdown_rx).await;
}

pub fn start_vrrp_listener(if_name: String) {
    let vrrp_sock_fd = match open_advertisement_socket(&if_name, true) {
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
        let vip_addresses = vrrp_pkt
            .vip_addresses
            .iter()
            .map(|address| format!("{} ", address.to_string()))
            .collect::<String>();

        info!(
            "VRRPv2 advertisement received: router id {} - prior {} - src {}.{}.{}.{}",
            router_id, priority, src_addr[0], src_addr[1], src_addr[2], src_addr[3]
        );

        info!("Virtual IPs: {}", vip_addresses);

        match vrrp_pkt.verify() {
            Ok(_) => {
                vrrp_pkt.print();
            }
            Err(err) => {
                warn!("Invalid VRRP packet received: {}", err);
            }
        }
    }
}
