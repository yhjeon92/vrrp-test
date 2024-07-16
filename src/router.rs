use core::fmt;
use std::{
    mem::size_of,
    net::Ipv4Addr,
    os::fd::{AsRawFd, OwnedFd},
    sync::Arc,
    thread::{self},
    time::Duration,
};

use arc_swap::ArcSwap;
use futures::FutureExt;
use log::{debug, error, info, warn};
use nix::{
    libc::{sockaddr, sockaddr_ll},
    sys::socket::{LinkAddr, MsgFlags, SockaddrIn, SockaddrLike},
};
use once_cell::sync::Lazy;
use tokio::{
    select,
    sync::mpsc::{Receiver, Sender},
};

use crate::{
    constants::{AF_PACKET, ETH_PROTO_ARP},
    interface::{add_ip_address, get_if_index},
    packet::{GarpPacket, VrrpV2Packet},
    VRouterConfig,
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
        }
    }
}

pub enum Event {
    Startup,
    _ShutDown,
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
            Event::AdvertReceived(rid, prior, src_addr) => write!(
                f,
                "AdvertReceived rid {} prio {} addr {}",
                rid,
                prior,
                src_addr.to_string()
            ),
            Event::AdvertTimeout => write!(f, "AdvertTimeout"),
            _ => write!(f, "Unknown"),
        }
    }
}

enum TimerEvent {
    ResetTimer,
    ResetInterval(f32),
}

impl fmt::Display for TimerEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            TimerEvent::ResetTimer => write!(f, "ResetTimer"),
            TimerEvent::ResetInterval(int) => {
                write!(f, "ResetInterval {}s", int)
            }
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
        config: VRouterConfig,
    ) -> Result<Router, String> {
        Ok(Router {
            state: State::Initialize,
            if_name,
            sock_fd: advert_sock_fd,
            arp_sock_fd,
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
    pub async fn start(&mut self) {
        info!("Router thread running...");

        let advert_pkt = match self.build_packet() {
            Some(pkt) => pkt.clone(),
            _ => {
                error!("Failed to build VRRP advertisement packet");
                return;
            }
        };

        info!("MASTER DOWN INTERVAL set to {}", self.master_down_int);

        // TODO: TEST
        let (advert_timer_tx, mut advert_timer_rx) =
            tokio::sync::mpsc::channel::<TimerEvent>(99999);

        let timer_int = self.master_down_int.clone();
        let timer_tx = self.router_tx.clone();

        let mut master_timer_jh = thread::spawn(move || {
            _ = futures::executor::block_on(master_down_timer(
                timer_int,
                timer_tx,
                advert_timer_rx,
            ));
        });

        // let mut master_timer_jh: JoinHandle<()> = tokio::task::spawn(master_down_timer(
        //     self.master_down_int,
        //     self.router_tx.clone(),
        //     advert_recv,
        // ));

        // main router loop
        loop {
            // match self.router_rx.blocking_recv() {
            match self.router_rx.recv().await {
                Some(event) => {
                    info!("{}", event);

                    match event {
                        Event::AdvertReceived(router_id, priority, src_addr) => match self.state {
                            State::Backup => {
                                info!(
                                    "\tAdvert router id {} - priority {} - src {}",
                                    router_id,
                                    priority,
                                    src_addr.to_string()
                                );

                                if router_id == self.router_id {
                                    if priority == 0 {
                                        MASTER_HEALTHY.store(Arc::new(false));

                                        // TODO: timer test
                                        _ = advert_timer_tx
                                            .send(TimerEvent::ResetInterval(self.skew_time))
                                            .await;

                                        // start_master_down_timer(
                                        //     self.skew_time,
                                        //     self.router_tx.clone(),
                                        // );
                                    } else {
                                        if !self.preempt_mode || priority >= self.priority {
                                            MASTER_HEALTHY.store(Arc::new(true));

                                            // TODO: timer test
                                            debug!("sending ResetTimer event...");
                                            _ = advert_timer_tx.send(TimerEvent::ResetTimer);
                                            // match advert_timer_tx.send(TimerEvent::ResetTimer).await
                                            // {
                                            //     Ok(()) => {
                                            //         debug!("Ok")
                                            //     }
                                            //     Err(err) => {
                                            //         debug!("{}", err.to_string());
                                            //     }
                                            // }

                                            // start_master_down_timer(
                                            //     self.master_down_int,
                                            //     self.router_tx.clone(),
                                            // );
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

                                        // TODO: timer test
                                        // _ = advert_timer_tx.blocking_send(TimerEvent::ResetTimer);
                                        _ = advert_timer_tx.send(TimerEvent::ResetTimer).await;
                                        // start_master_down_timer(
                                        //     self.master_down_int,
                                        //     self.router_tx.clone(),
                                        // );

                                        // Transition to Backup
                                        info!("Advertisement of priority {} received from src {}, transitioning to BACKUP state...", priority, src_addr.to_string());
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
                                        match add_ip_address(&self.if_name, self.virtual_ip) {
                                            Ok(_) => {}
                                            Err(err) => {
                                                error!("Failed to add IP address {} to interface {}: {}", self.virtual_ip.to_string(), &self.if_name, err);
                                            }
                                        }

                                        // Promote oneself to Master
                                        self.state = State::Master;
                                    } else {
                                        // Set Master Down Timer interval to MasterDownInterval
                                        // TODO: timer test
                                        // _ = advert_timer_tx.blocking_send(TimerEvent::ResetTimer);
                                        _ = advert_timer_tx.send(TimerEvent::ResetTimer).await;

                                        // start_master_down_timer(
                                        //     self.master_down_int,
                                        //     self.router_tx.clone(),
                                        // );

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
                                match add_ip_address(&self.if_name, self.virtual_ip) {
                                    Ok(_) => {}
                                    Err(err) => {
                                        error!(
                                            "Failed to add IP address {} to interface {}: {}",
                                            self.virtual_ip.to_string(),
                                            &self.if_name,
                                            err
                                        );
                                    }
                                }

                                warn!("Master down interval expired. Transitioning to MASTER state...");
                                self.state = State::Master;
                            }
                            _ => {
                                // TODO
                            }
                        },
                        Event::_ShutDown => match self.state {
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
                    warn!("No Event!");
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
        Ok(_) => {
            debug!("Sent VRRP advertisement");
        }
        Err(err) => {
            warn!("Failed to send VRRP advertisement: {}", err.to_string());
        }
    }
}

pub fn send_gratuitous_arp(sock_fd: i32, if_name: String, router_id: u8, virtual_ip: Ipv4Addr) {
    let mut pkt = GarpPacket::new(virtual_ip, router_id);

    unsafe {
        debug!("interface {} len {}", if_name, if_name.len());

        let if_index = match get_if_index(&if_name) {
            Ok(ind) => ind,
            Err(err) => {
                error!("{}", err);
                return;
            }
        };

        debug!("IF_INDEX {}", if_index);

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
                error!("Failed to construct sockaddr");
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
                info!("Sent a GARP of len {}", size);
            }
            Err(err) => {
                warn!(
                    "An error was encountered while sending GARP request! {}",
                    err.to_string()
                );
            }
        }
    }
}

pub fn start_advert_timer(advert_int: u8, sock_fd: i32, pkt_vec: Vec<u8>, tx: Sender<Event>) {
    thread::spawn(move || {
        send_advertisement(sock_fd, pkt_vec);
        thread::sleep(Duration::from_secs(advert_int as u64));
        // TODO: async test
        _ = tx.blocking_send(Event::AdvertTimeout);
    });
}

async fn master_down_timer(interval: f32, tx: Sender<Event>, mut rx: Receiver<TimerEvent>) {
    let mut timer_int = interval.clone();
    loop {
        let event = tokio::select! {
            () = master_down_timer_task(interval, tx.clone()) => {
                break;
            },
            Some(event) = rx.recv() => {
                debug!("received event!");
                event
            },
        };

        debug!("timer received event: {}", event);
        debug!("select! poll finished");

        // match rx.recv().await {
        //     Some(event) => match event {
        //         TimerEvent::ResetTimer => {
        //             debug!("Received master down timer reset event");
        //         }
        //         TimerEvent::ResetInterval(int) => {
        //             debug!("Resetting master down timer interval to {} s...", int);
        //             timer_int = int;
        //         }
        //     },
        //     None => {
        //         debug!("no valid event!");
        //     }
        // }

        // select! {
        //     () = master_down_timer_task(timer_int, tx.clone()).fuse() => {}
        //     result = rx.recv().fuse() => {
        //         match result {
        //             Some(event) => {
        //                 match event {
        //                     TimerEvent::ResetTimer => {
        //                         debug!("Received master down timer reset event");
        //                     },
        //                     TimerEvent::ResetInterval(int) => {
        //                         debug!("Resetting master down timer interval to {} s...", int);
        //                         timer_int = int;
        //                     },
        //                 }
        //             },
        //             None => {},
        //         }
        //     }
        //     complete => {},
        // }

        // tokio::select! {
        //     _ = master_down_timer_task(timer_int, tx.clone()) => {}
        //     _ = rx.recv() => {
        //         debug!("Received master down timer reset event");
        //     }
        // };

        // match res {
        //     Some(event) => match event {
        //         TimerEvent::ResetTimer => {
        //             debug!("Resetting master down timer...");
        //         }
        //         TimerEvent::ResetInterval(int) => {
        //
        //             timer_int = int;
        //         }
        //     },
        //     None => {
        //         // TODO: redundant?
        //         break;
        //     }
        // }
    }
}

async fn master_down_timer_task(interval: f32, tx: Sender<Event>) {
    thread::sleep(Duration::from_millis((interval * 1000 as f32) as u64));
    warn!("Master Unhealthy");
    // _ = tx.blocking_send(Event::MasterDown);
    _ = tx.send(Event::MasterDown).await;
}
