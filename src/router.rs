use core::fmt;
use std::{
    net::Ipv4Addr,
    os::fd::{AsRawFd, OwnedFd},
    sync::Arc,
    thread,
    time::Duration,
};

use arc_swap::ArcSwap;
use nix::{
    libc::{sockaddr, sockaddr_ll},
    sys::socket::{LinkAddr, MsgFlags, SockaddrIn, SockaddrLike},
    NixPath,
};
use once_cell::sync::Lazy;
use tokio::sync::mpsc::{Receiver, Sender};

use crate::{
    constants::{AF_PACKET, ETH_PROTO_ARP},
    interface::add_ip_address,
    packet::GarpPacket,
    VrrpV2Packet, CONFIG,
};

pub enum State {
    Initialize,
    Backup,
    Master,
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            State::Initialize => write!(f, "Initialize"),
            State::Backup => write!(f, "Backup"),
            State::Master => write!(f, "Master"),
            _ => write!(f, "Unknown"),
        }
    }
}

pub enum Event {
    Startup,
    ShutDown,
    MasterDown,
    // RouterId - Priority - Source
    AdvertReceived(u8, u8, Ipv4Addr),
    AdvertTimeout,
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Event::Startup => write!(f, "StartUp"),
            Event::MasterDown => write!(f, "MasterDown"),
            Event::AdvertReceived(_, _, _) => write!(f, "AdvertReceived"),
            Event::AdvertTimeout => write!(f, "AdvertTimeout"),
            _ => write!(f, "Unknown"),
        }
    }
}

static MASTER_HEALTHY: Lazy<ArcSwap<bool>> = Lazy::new(|| ArcSwap::from_pointee(false));

pub struct Router {
    state: State,
    if_name: String,
    sock_fd: OwnedFd,
    arp_sock_fd: OwnedFd,
    router_id: u8,
    priority: u8,
    advert_int: u8,
    master_down_int: f32,
    skew_time: f32,
    preempt_mode: bool,
    virtual_ip: Ipv4Addr,
    router_tx: Sender<Event>,
    router_rx: Receiver<Event>,
}

impl Router {
    pub fn new(
        if_name: String,
        advert_sock_fd: OwnedFd,
        arp_sock_fd: OwnedFd,
        tx: Sender<Event>,
        rx: Receiver<Event>,
    ) -> Result<Router, String> {
        let config = CONFIG.load_full();

        Ok(Router {
            state: State::Initialize,
            if_name: if_name,
            sock_fd: advert_sock_fd,
            arp_sock_fd: arp_sock_fd,
            router_id: config.router_id,
            priority: config.priority,
            advert_int: config.advert_int,
            master_down_int: (3 as f32 * config.advert_int as f32)
                + ((256 as u16 - config.priority as u16) as f32 / 256 as f32),
            skew_time: ((256 as u16 - config.priority as u16) as f32 / 256 as f32),
            preempt_mode: true,
            virtual_ip: config.virtual_ip,
            router_tx: tx,
            router_rx: rx,
        })
    }

    // RFC 3768 Protocol State Machine
    pub fn start(&mut self) {
        println!("Router thread running...");

        let advert_pkt = match self.build_packet() {
            Some(pkt) => pkt.clone(),
            _ => {
                println!("[ERROR] failed to build VRRP advertisement packet");
                return;
            }
        };

        println!("MASTER DOWN INTERVAL SET TO {}", self.master_down_int);

        // main router loop
        loop {
            match self.router_rx.blocking_recv() {
                Some(event) => {
                    println!("{}", event);

                    match event {
                        Event::AdvertReceived(router_id, priority, src_addr) => match self.state {
                            State::Backup => {
                                println!(
                                    "\tAdvert router id {} - priority {} - src {}",
                                    router_id,
                                    priority,
                                    src_addr.to_string()
                                );

                                if router_id == self.router_id {
                                    if priority == 0 {
                                        MASTER_HEALTHY.store(Arc::new(false));

                                        start_master_down_timer(
                                            self.skew_time,
                                            self.router_tx.clone(),
                                        );
                                    } else {
                                        if !self.preempt_mode || priority >= self.priority {
                                            MASTER_HEALTHY.store(Arc::new(true));

                                            start_master_down_timer(
                                                self.master_down_int,
                                                self.router_tx.clone(),
                                            );
                                        }
                                    }
                                }
                            }
                            State::Master => {
                                if router_id == self.router_id {
                                    if priority == 0 {
                                        send_advertisement(
                                            self.sock_fd.as_raw_fd(),
                                            advert_pkt.clone(),
                                        );
                                        // Set advert timer to advert_int
                                    } else if priority > self.priority {
                                        // Stop advert timer
                                        // Set master down timer
                                        MASTER_HEALTHY.store(Arc::new(true));

                                        start_master_down_timer(
                                            self.master_down_int,
                                            self.router_tx.clone(),
                                        );

                                        // Transition to Backup
                                        println!("Advertisement of priority {} received from src {}, transitioning to BACKUP state...", priority, src_addr.to_string());
                                        self.state = State::Backup;
                                    }
                                }
                            }
                            _ => {}
                        },
                        Event::Startup => {
                            // TODO: Startup
                            match self.state {
                                State::Initialize => {
                                    // Do things..
                                    if self.priority == 255 {
                                        // Multicast Advertisement
                                        send_advertisement(
                                            self.sock_fd.as_raw_fd(),
                                            advert_pkt.clone(),
                                        );

                                        // Broadcast Gratuitous ARP
                                        send_gratuitous_arp(
                                            self.arp_sock_fd.as_raw_fd(),
                                            self.if_name.clone(),
                                            self.router_id,
                                            self.virtual_ip,
                                        );

                                        // Start advertisement timer
                                        start_advert_timer(
                                            self.advert_int,
                                            self.sock_fd.as_raw_fd(),
                                            advert_pkt.clone(),
                                            self.router_tx.clone(),
                                        );

                                        // TODO: Set Virtual IP to an interface
                                        match add_ip_address(
                                            &self.sock_fd,
                                            &self.if_name,
                                            self.virtual_ip,
                                        ) {
                                            Ok(_) => {}
                                            Err(err) => {
                                                println!("[ERROR] {}", err);
                                            }
                                        }

                                        // Promote oneself to Master
                                        self.state = State::Master;
                                    } else {
                                        // Set Master Down Timer interval to MasterDownInterval
                                        start_master_down_timer(
                                            self.master_down_int,
                                            self.router_tx.clone(),
                                        );

                                        self.state = State::Backup;
                                    }
                                }
                                _ => (),
                            }
                        }
                        Event::AdvertTimeout => match self.state {
                            State::Master => {
                                start_advert_timer(
                                    self.advert_int,
                                    self.sock_fd.as_raw_fd(),
                                    advert_pkt.clone(),
                                    self.router_tx.clone(),
                                );
                            }
                            _ => {
                                // Discard
                            }
                        },
                        Event::MasterDown => match self.state {
                            State::Backup => {
                                // Multicast Advertisement
                                send_advertisement(self.sock_fd.as_raw_fd(), advert_pkt.clone());

                                // Broadcast Gratuitous ARP
                                send_gratuitous_arp(
                                    self.arp_sock_fd.as_raw_fd(),
                                    self.if_name.clone(),
                                    self.router_id,
                                    self.virtual_ip,
                                );

                                // Start advertisement timer
                                start_advert_timer(
                                    self.advert_int,
                                    self.sock_fd.as_raw_fd(),
                                    advert_pkt.clone(),
                                    self.router_tx.clone(),
                                );

                                // TODO: Set Virtual IP to an interface
                                match add_ip_address(&self.sock_fd, &self.if_name, self.virtual_ip)
                                {
                                    Ok(_) => {}
                                    Err(err) => {
                                        println!("[ERROR] {}", err);
                                    }
                                }

                                println!("Master down interval expired. Transitioning to MASTER state...");
                                self.state = State::Master;
                            }
                            _ => {
                                // TODO
                            }
                        },
                        Event::ShutDown => match self.state {
                            State::Backup => {
                                // Stop MasterDown timer
                                self.state = State::Initialize;
                            }
                            State::Master => {}
                            _ => {}
                        },
                    };
                }
                _ => {
                    std::thread::sleep(std::time::Duration::from_secs(1));
                    println!("No Event!");
                }
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
        Ok(_) => {}
        Err(err) => {
            println!(
                "An error was encountered while sending packet! {}",
                err.to_string()
            );
        }
    }
}

pub fn send_gratuitous_arp(sock_fd: i32, if_name: String, router_id: u8, virtual_ip: Ipv4Addr) {
    let mut pkt = GarpPacket::new(virtual_ip, router_id);

    unsafe {
        println!("interface {} len {}", if_name, if_name.len());

        let if_index = match nix::net::if_::if_nameindex() {
            Ok(ifs) => {
                let mut index: i32 = -1;
                for interface in ifs.iter() {
                    let if_name_target = match interface.name().to_str() {
                        Ok(name) => name,
                        Err(err) => {
                            println!("Error.. {}", err.to_string());
                            return;
                        }
                    };

                    println!(
                        "Interface {} Len {}",
                        if_name_target,
                        interface.name().len()
                    );

                    if if_name.eq(if_name_target) {
                        index = interface.index() as i32;
                        println!("Found interface {}", if_name);
                        break;
                    }
                }

                match index {
                    -1 => {
                        println!("Error..");
                        return;
                    }
                    ind => ind as usize,
                }
            }
            Err(err) => {
                println!("[ERROR] {}", err.to_string());
                return;
            }
        };

        println!("IF_INDEX {}", if_index);

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
                println!("[ERROR] failed to instantiate sockaddr");
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
                println!("Sent a GARP of len {}", size);
            }
            Err(err) => {
                println!(
                    "An error was encountered while sending GARP request! {}",
                    err.to_string()
                );
            }
        }
    }
}

pub fn start_master_down_timer(interval: f32, tx: Sender<Event>) {
    thread::spawn(move || {
        thread::sleep(Duration::from_millis((interval * 1000 as f32) as u64));

        if !**MASTER_HEALTHY.load() {
            println!("Master Unhealthy");
            _ = tx.blocking_send(Event::MasterDown);
        } else {
            MASTER_HEALTHY.store(Arc::new(false));
            println!("Master Healthy, skipping..");
        }
    });
}

pub fn start_advert_timer(advert_int: u8, sock_fd: i32, pkt_vec: Vec<u8>, tx: Sender<Event>) {
    thread::spawn(move || {
        send_advertisement(sock_fd, pkt_vec);
        thread::sleep(Duration::from_secs(advert_int as u64));
        _ = tx.blocking_send(Event::AdvertTimeout);
    });
}
