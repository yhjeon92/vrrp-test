use core::fmt;
use std::{
    borrow::Borrow,
    convert::TryInto,
    net::Ipv4Addr,
    os::fd::{AsRawFd, OwnedFd},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use arc_swap::ArcSwap;
use nix::sys::socket::{MsgFlags, SockaddrIn};
use once_cell::sync::Lazy;
use tokio::{
    sync::mpsc::{Receiver, Sender},
    time::{interval, Interval},
};

use crate::{VrrpV2Packet, ADVERT, CONFIG};

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
static ADVERT_EXPIRED: Lazy<ArcSwap<bool>> = Lazy::new(|| ArcSwap::from_pointee(true));

pub struct Router {
    state: State,
    sock_fd: OwnedFd,
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
    pub fn new(fd: OwnedFd, tx: Sender<Event>, rx: Receiver<Event>) -> Router {
        let config = CONFIG.load_full();

        Router {
            state: State::Initialize,
            sock_fd: fd,
            router_id: config.router_id,
            priority: config.priority,
            advert_int: config.advert_int,
            master_down_int: (3 as f32 * config.advert_int as f32)
                + ((256 as u16 - config.priority as u16) as f32 / 256 as f32),
            skew_time: ((256 as u16 - config.priority as u16) as f32 / 256 as f32),
            preempt_mode: false,
            virtual_ip: config.virtual_ip,
            router_tx: tx,
            router_rx: rx,
        }
    }

    // RFC 3768 Protocol State Machine
    pub fn start(&mut self) {
        println!("Router thread running...");

        let sock_fd = self.sock_fd.as_raw_fd().clone();

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

                    let master_down_int = self.master_down_int;
                    let tx = self.router_tx.clone();

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
                                    MASTER_HEALTHY.store(Arc::new(true));

                                    thread::spawn(move || {
                                        start_master_down_timer(master_down_int, tx)
                                    });
                                }
                            }
                            State::Master => {
                                if router_id == self.router_id {
                                    if priority == 0 {
                                        send_advertisement(sock_fd, advert_pkt.clone());
                                        // Set advert timer to advert_int
                                    } else if priority > self.priority {
                                        // Stop advert timer
                                        // Set master down timer
                                        MASTER_HEALTHY.store(Arc::new(true));

                                        thread::spawn(move || {
                                            start_master_down_timer(master_down_int, tx)
                                        });

                                        // Transition to Backup
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
                                        send_advertisement(sock_fd, advert_pkt.clone());
                                    } else {
                                        // Set Master Down Timer interval to MasterDownInterval
                                        self.state = State::Backup;
                                    }

                                    thread::spawn(move || {
                                        start_master_down_timer(master_down_int, tx)
                                    });
                                }
                                _ => (),
                            }
                        }
                        Event::AdvertTimeout => match self.state {
                            State::Master => {
                                let advert_int_cloned = self.advert_int.clone();
                                let sock_fd_cloned = sock_fd.clone();
                                let pkt_vec = advert_pkt.clone();
                                let tx = self.router_tx.clone();
                                thread::spawn(move || {
                                    start_advert_timer(
                                        advert_int_cloned,
                                        sock_fd_cloned,
                                        pkt_vec,
                                        tx,
                                    )
                                });
                            }
                            _ => {
                                // Discard
                            }
                        },
                        Event::MasterDown => match self.state {
                            State::Backup => {
                                println!("MASTER DOWN!");
                                // Multicast Advertisement
                                // Broadcast Gratuitous ARP
                                // Start advertisement timer
                                let advert_int_cloned = self.advert_int.clone();
                                let sock_fd_cloned = sock_fd.clone();
                                let pkt_vec = advert_pkt.clone();

                                thread::spawn(move || {
                                    start_advert_timer(
                                        advert_int_cloned,
                                        sock_fd_cloned,
                                        pkt_vec,
                                        tx,
                                    )
                                });

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
                        _ => {}
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

fn start_timer(int: u64) {
    let mut iter = 0;
    loop {
        thread::sleep(Duration::from_micros(int));
        iter += 1;
        if iter > 1000000 {
            println!("a million iteration is reached");
            iter = 0;
        }
        // Do things
    }
}

pub fn start_master_down_timer(master_down_int: f32, tx: Sender<Event>) {
    thread::sleep(Duration::from_millis(
        (master_down_int * 1000 as f32) as u64,
    ));

    if !**MASTER_HEALTHY.load() {
        println!("Master Unhealthy");
        _ = tx.blocking_send(Event::MasterDown);
    } else {
        MASTER_HEALTHY.store(Arc::new(false));
        println!("Master Healthy, skipping..");
    }
}

pub fn start_advert_timer(advert_int: u8, sock_fd: i32, pkt_vec: Vec<u8>, tx: Sender<Event>) {
    send_advertisement(sock_fd, pkt_vec);
    thread::sleep(Duration::from_secs(advert_int as u64));
    _ = tx.blocking_send(Event::AdvertTimeout);
}
