mod constants;
mod interface;
mod packet;
mod router;
mod socket;

use core::fmt;
use std::{fs::File, io::{ErrorKind, Read}, net::Ipv4Addr, str::FromStr};

use interface::get_if_index;
use log::{debug, error, info, warn};
use packet::{NetLinkAttribute, VrrpV2Packet};
use router::{Event, Router};
use serde::{
    de::Error,
    {Deserialize, Serialize},
};
use socket::{open_advertisement_monitor_socket, open_advertisement_socket, open_arp_socket, open_netlink_monitor_socket, recv_nl_packet, recv_vrrp_packet};
use tokio::{io::unix::AsyncFd, sync::mpsc::{self, channel, Receiver, Sender}, task::JoinSet};

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

pub async fn start_vrouter(config: VRouterConfig, mut shutdown_rx: Receiver<()>) -> Result<(), String> {
    let (tx_vrrp, mut rx_vrrp) = mpsc::channel::<VrrpV2Packet>(1);
    let (tx_netlink, mut rx_netlink) = mpsc::channel::<Vec<NetLinkAttribute>>(1);

    let (tx_router, rx_router) = mpsc::channel::<Event>(3);

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
            return Err(format!("Failed to open a socket: {}, exiting...", err.to_string()));
            
        }
    };

    let arp_sock_fd = match open_arp_socket(&if_name) {
        Ok(fd) => fd,
        Err(err) => {
            return Err(format!(
                "Failed to open an arp socket: {}, exiting...",
                err.to_string()
            ));
        }
    };

    let mut router = match Router::new(
        if_name,
        match vrrp_sock_fd.try_clone() {
            Ok(fd) => fd,
            Err(err) => {
                return Err(format!("Failed to clone socket fd: {}, exiting...", err.to_string()));
            }
        },
        arp_sock_fd,
        tx_router.clone(),
        rx_router,
        config.clone(),
    ) {
        Ok(router) => router,
        Err(err) => {
            return Err(format!(
                "Failed to initialize a router: {}, exiting...",
                err.to_string()
            ));
        }
    };

    tokio::spawn(async move { router.start().await });

    let tx_handle = tx_router.clone();

    match tx_router.send(Event::Startup).await {
        Ok(()) => {
            // do nothing
        }
        Err(err) => {
            return Err(format!("Failed to start a router: {}, exiting...", err.to_string()));
        }
    }

    info!("Router Startup");
    info!("Listening for vRRPv2 packets...");

    let mut js = match start_monitor_task(
        &config.interface, 
        match config.unicast_peers {
            Some(_) => false,
            None => true,
        },
        tx_vrrp, 
        tx_netlink
    ).await {
        Ok(handles) => handles,
        Err(err) => {
            return Err(format!("Failed to start monitoring tasks: {}, exiting...", err.to_string()));
        }
    };

    loop {
        tokio::select! {
            Some(vrrp_pkt) = rx_vrrp.recv() => {
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

                        match tx_router.send(Event::AdvertReceived(
                            router_id,
                            priority,
                            Ipv4Addr::from(src_addr),
                            vrrp_pkt.vip_addresses,
                        )).await {
                            Ok(()) => {}
                            Err(err) => {
                                return Err(format!("Failed to send event: {}, exiting...", err.to_string()));
                            }
                        }
                    }
                    Err(err) => {
                        warn!("Invalid VRRP packet received: {}", err);
                    }
                }
            },
            Some(attrs) = rx_netlink.recv() => {
                info!("Received Netlink Event");
                // TODO: Filter here, if anything happens to the primary address send to router
                for attr in attrs.iter() {
                    attr.print();
                }
            },
            Some(()) = shutdown_rx.recv() => {
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

                js.abort_all();

                break;
            },
            else => {
                // No Action
            }
        }
    }

    js.abort_all();

    info!("virtual router terminated");

    Ok(())
}

pub async fn start_vrouter_cfile(config_file_path: String, shutdown_rx: Receiver<()>) -> Result<(), String> {
    let config = match read_config(&config_file_path) {
        Some(config) => config,
        None => {
            return Err(format!("Failed to read configuration from file {}", &config_file_path));
        }
    };

    start_vrouter(config, shutdown_rx).await?;

    Ok(())
}

pub async fn start_listener(if_name: String, mut shutdown_rx: Receiver<()>) -> Result<(), String> {
    let (tx_vr, mut rx_vr) = channel::<VrrpV2Packet>(1);
    let (tx_nl, mut rx_nl) = channel::<Vec<NetLinkAttribute>>(1);
    
    let mut js = match start_monitor_task(&if_name, true, tx_vr, tx_nl).await {
        Ok(handles) => handles,
        Err(err) => {
            return Err(err);
        }
    };

    info!("Starting to monitor interface {}", if_name);

    loop {
        tokio::select! {
            Some(pkt) = rx_vr.recv() => {
                info!("Received VRRP advertisement");
                pkt.print();
            },
            Some(attrs) = rx_nl.recv() => {
                info!("Received Netlink Event");
                for attr in attrs.iter() {
                    attr.print();
                }
            },
            Some(()) = shutdown_rx.recv() => {
                debug!("Stopping a listener thread");

                js.abort_all();
                break;
            },
            else => {
                // No Action
            },
        }
    };

    debug!("[TEST] Stopping Listener..");

    Ok(())
}

async fn start_monitor_task(if_name: &str, advert_multicast: bool, tx_vrrp: Sender<VrrpV2Packet>, tx_netlink: Sender<Vec<NetLinkAttribute>>)
    -> Result<JoinSet<()>, String>
{
    let mut tasks = JoinSet::new();

    let vrrp_sock = open_advertisement_monitor_socket(if_name, advert_multicast)?;

    let nl_sock = open_netlink_monitor_socket()?;

    let if_ind = match get_if_index(if_name) {
        Ok(ind) => ind,
        Err(err) => {
            error!("{}", err);
            return Err("".to_string());
        }
    };

    let mut pkt_buf: [u8; 1024] = [0u8; 1024];
    let mut nl_pkt_buf: [u8; 1024] = [0u8; 1024];

    info!("Starting to monitor interface {}", if_name);
    
    tasks.spawn(async move {
        loop {
            match vrrp_sock.readable().await {
                Ok(mut fd_guard) => {
                    match fd_guard.try_io(|guard| {
                        let fd = guard.get_ref();
                        match recv_vrrp_packet(fd, &mut pkt_buf) {
                            Ok(pkt) => {
                                tx_vrrp.blocking_send(pkt).or(Err(std::io::Error::last_os_error()))
                            },
                            Err(err) => {
                                // warn!("Fail VR {}", err);
                                warn!("Reading VRRP packet failed: {}", err);
                                Err(std::io::Error::last_os_error())
                            },
                        }
                    }) {
                        Ok(Ok(())) => {
                            debug!("[TEST] VRRP Success");
                        },
                        Ok(Err(err)) => {
                            debug!("[TEST] VRRP internal error from channel i/o: {}", err.to_string());
                        },
                        Err(_err) => {
                            warn!("[TEST] AsyncFdTryIOError");
                            break;
                        },
                    };
                },
                Err(err) => {
                    error!("I/O Error: {}", err.to_string());
                    break;
                },
            }
        }
    });

    tasks.spawn(async move {
        loop {
            match nl_sock.readable().await {
                Ok(mut fd_guard) => {
                    match fd_guard.try_io(|guard| {
                        let fd = guard.get_ref();
                        match recv_nl_packet(fd, &mut nl_pkt_buf, if_ind) {
                            Ok(attributes) => {
                                tx_netlink.blocking_send(attributes).or(Err(std::io::Error::last_os_error()))
                            },
                            Err(err) => {
                                warn!("Reading Netlink packet failed: {}", err);
                                Err(std::io::Error::last_os_error())
                            }
                        }
                    }) {
                        Ok(Ok(())) => {
                            debug!("[TEST] NL Success");
                        },
                        Ok(Err(err)) => {
                            debug!("[TEST] NL internal error from channel i/o: {}", err.to_string());
                        },
                        Err(_err) => {
                            warn!("[TEST] AsyncFdTryIOError");
                            break;
                        },
                    }
                },
                Err(err) => {
                    error!("I/O Error: {}", err.to_string());
                    break;
                },
            }
        }
    });

    Ok(tasks)
}
