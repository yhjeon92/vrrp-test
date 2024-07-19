use core::fmt;
use std::{
    mem::size_of,
    net::Ipv4Addr,
    os::fd::{AsRawFd, OwnedFd},
    time::Duration,
};

use log::{debug, error, info, warn};
use nix::sys::socket::{MsgFlags, SockaddrIn};
use tokio::sync::mpsc::{channel, Receiver, Sender};

use crate::{
    interface::{add_ip_address, del_ip_address, get_ip_address},
    packet::VrrpV2Packet,
    socket::send_gratuitous_arp,
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
            _ => write!(f, "Unknown"),
        }
    }
}

enum TimerEvent {
    ResetTimer,
    ResetInterval(f32),
    Abort,
}

impl fmt::Display for TimerEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            TimerEvent::ResetTimer => write!(f, "ResetTimer"),
            TimerEvent::ResetInterval(int) => {
                write!(f, "ResetInterval {}s", int)
            }
            TimerEvent::Abort => {
                write!(f, "Abort")
            }
        }
    }
}

pub struct Router {
    state: State,
    if_name: String,
    local_addr: Ipv4Addr,
    sock_fd: OwnedFd,
    arp_sock_fd: OwnedFd,
    router_id: u8,
    priority: u8,
    advert_int: u8,
    master_down_int: f32,
    skew_time: f32,
    preempt_mode: bool,
    virtual_ip: (Ipv4Addr, u8),
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
        let local_addr = match get_ip_address(&if_name) {
            Ok(addr) => addr,
            Err(err) => {
                error!("Failed to initialize router: {}", err);
                return Err(err);
            }
        };

        Ok(Router {
            state: State::Initialize,
            if_name,
            local_addr,
            sock_fd: advert_sock_fd,
            arp_sock_fd,
            router_id: config.router_id,
            priority: config.priority,
            advert_int: config.advert_int,
            master_down_int: (3 as f32 * config.advert_int as f32)
                + ((256 as u16 - config.priority as u16) as f32 / 256 as f32),
            skew_time: ((256 as u16 - config.priority as u16) as f32 / 256 as f32),
            preempt_mode: true,
            virtual_ip: (config.virtual_ip, config.netmask_len),
            router_tx: tx,
            router_rx: rx,
        })
    }

    // RFC 3768 Protocol State Machine
    pub async fn start(&mut self) {
        info!("Router thread running...");

        let advert_pkt = self.build_packet();

        info!("MASTER DOWN INTERVAL set to {}", self.master_down_int);

        let mut master_timer_tx: Option<Sender<TimerEvent>> = None;
        let mut advert_timer_tx: Option<Sender<TimerEvent>> = None;

        // main router loop
        loop {
            match self.router_rx.recv().await {
                Some(event) => {
                    debug!("{}", event);

                    match event {
                        Event::Startup => {
                            // TODO: Startup
                            match self.state {
                                State::Initialize => {
                                    // Do things..
                                    if self.priority == 0xFF {
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

                                        // Add Virtual IP to the interface
                                        match add_ip_address(&self.if_name, self.virtual_ip) {
                                            Ok(_) => {}
                                            Err(err) => {
                                                error!("Failed to add IP address {}/{} to interface {}: {}", self.virtual_ip.0.to_string(), self.virtual_ip.1, &self.if_name, err);
                                                error!("exiting...");
                                                return;
                                            }
                                        }

                                        // Start advertisement timer
                                        advert_timer_tx = Some(start_advert_timer(
                                            self.advert_int,
                                            self.sock_fd.as_raw_fd(),
                                            advert_pkt.clone(),
                                        ));

                                        // Stop master down timer
                                        match master_timer_tx {
                                            Some(ref tx) => _ = tx.send(TimerEvent::Abort).await,
                                            None => { /*  */ }
                                        };

                                        // Promote oneself to Master
                                        info!("Promoting to MASTER state..");
                                        self.state = State::Master;
                                    } else {
                                        // Start master down timer
                                        master_timer_tx = Some(start_master_down_timer(
                                            self.master_down_int,
                                            self.router_tx.clone(),
                                        ));

                                        // Promote oneself to BACKUP
                                        info!("Promoting to BACKUP state..");
                                        self.state = State::Backup;
                                    }
                                }
                                _ => (),
                            }
                        }
                        Event::AdvertReceived(router_id, priority, src_addr) => match self.state {
                            State::Backup => {
                                debug!(
                                    "\tAdvert router id {} - priority {} - src {}",
                                    router_id,
                                    priority,
                                    src_addr.to_string()
                                );

                                if router_id == self.router_id {
                                    if priority == 0 {
                                        // Reset master down timer to skew_time
                                        warn!("VRRPv2 advert of priority 0 received.");
                                        match master_timer_tx {
                                            Some(ref tx) => {
                                                _ = tx
                                                    .send(TimerEvent::ResetInterval(self.skew_time))
                                                    .await
                                            }
                                            None => {
                                                error!("cannot find master down timer binding, exiting..");
                                                return;
                                            }
                                        };
                                    } else {
                                        if !self.preempt_mode || priority >= self.priority {
                                            // Master healthy. Resetting master down timer
                                            match master_timer_tx {
                                                Some(ref tx) => {
                                                    _ = tx.send(TimerEvent::ResetTimer).await
                                                }
                                                None => {
                                                    error!("cannot find master down timer binding, exiting..");
                                                    return;
                                                }
                                            }
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
                                        match advert_timer_tx {
                                            Some(ref tx) => {
                                                _ = tx
                                                    .send(TimerEvent::ResetInterval(
                                                        self.advert_int as f32,
                                                    ))
                                                    .await;
                                            }
                                            None => { /* */ }
                                        }
                                        // Received an Advert with higher priority - demoting to BACKUP
                                    } else if (!self.preempt_mode || priority > self.priority)
                                        || (priority == self.priority && src_addr > self.local_addr)
                                    {
                                        // Delete virtual ip bound to interface
                                        match del_ip_address(&self.if_name, self.virtual_ip) {
                                            Ok(_) => {}
                                            Err(err) => {
                                                error!("Failed to delete IP address {}/{} from interface {}: {}", self.virtual_ip.0.to_string(), self.virtual_ip.1, &self.if_name, err);
                                                error!("exiting...");
                                                return;
                                            }
                                        }
                                        // Stop advert timer
                                        match advert_timer_tx {
                                            Some(ref tx) => {
                                                _ = tx.send(TimerEvent::Abort).await;
                                            }
                                            None => {
                                                error!("Failed to find bindings for advert timer!");
                                            }
                                        };

                                        advert_timer_tx = None;

                                        // Transition to Backup
                                        info!("Received VRRP advert from src {} with priority {}, higher than priority of local node {}",
                                            src_addr.to_string(),
                                            priority,
                                            self.priority);

                                        // Start master down timer
                                        master_timer_tx = Some(start_master_down_timer(
                                            self.master_down_int,
                                            self.router_tx.clone(),
                                        ));
                                        info!("Demoting to BACKUP state..");
                                        self.state = State::Backup;
                                    }
                                }
                            }
                            _ => {}
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
                                advert_timer_tx = Some(start_advert_timer(
                                    self.advert_int,
                                    self.sock_fd.as_raw_fd(),
                                    advert_pkt.clone(),
                                ));

                                // TODO: Set Virtual IP to an interface
                                match add_ip_address(&self.if_name, self.virtual_ip) {
                                    Ok(_) => {}
                                    Err(err) => {
                                        error!(
                                            "Failed to add IP address {}/{} to interface {}: {}",
                                            self.virtual_ip.0.to_string(),
                                            self.virtual_ip.1,
                                            &self.if_name,
                                            err
                                        );
                                    }
                                }

                                warn!("Master down interval expired.");
                                // Stop master down timer
                                match master_timer_tx {
                                    Some(ref tx) => _ = tx.send(TimerEvent::Abort).await,
                                    None => { /*  */ }
                                };

                                info!("Promoting to MASTER state..");
                                self.state = State::Master;
                            }
                            _ => {
                                // TODO
                            }
                        },
                        Event::_ShutDown => match self.state {
                            State::Backup => {
                                // Stop master down timer
                                match master_timer_tx {
                                    Some(ref tx) => _ = tx.send(TimerEvent::Abort).await,
                                    None => { /*  */ }
                                };

                                // Demote to initialize state
                                info!("Demoting to INITIALIZE state..");
                                self.state = State::Initialize;
                                std::process::exit(1);
                            }
                            State::Master => {
                                // Stop advert timer
                                match advert_timer_tx {
                                    Some(ref tx) => _ = tx.send(TimerEvent::Abort).await,
                                    None => { /* */ }
                                };
                                // TODO: Send an advert with priority = 0
                                let pkt = self.build_packet_with_priority(0);
                                send_advertisement(self.sock_fd.as_raw_fd(), pkt);

                                // Demote to initialize state
                                info!("Demoting to INITIALIZE state..");
                                self.state = State::Initialize;
                            }
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

    fn build_packet(&self) -> Vec<u8> {
        let mut pkt_hdr = VrrpV2Packet::new();
        pkt_hdr.router_id = self.router_id;
        pkt_hdr.priority = self.priority;
        pkt_hdr.cnt_ip_addr = 1;
        pkt_hdr.auth_type = 1;
        pkt_hdr.advert_int = self.advert_int;

        let mut vip_addresses: Vec<Ipv4Addr> = Vec::new();
        vip_addresses.push(self.virtual_ip.0);

        pkt_hdr.set_vip_addresses(&vip_addresses);

        // TODO
        let auth_data = [49, 49, 49, 49, 0, 0, 0, 0].to_vec();

        pkt_hdr.set_auth_data(&auth_data);

        pkt_hdr.to_bytes()
    }

    fn build_packet_with_priority(&self, priority: u8) -> Vec<u8> {
        let mut pkt_hdr = VrrpV2Packet::new();
        pkt_hdr.router_id = self.router_id;
        pkt_hdr.priority = priority;
        pkt_hdr.cnt_ip_addr = 1;
        pkt_hdr.auth_type = 1;
        pkt_hdr.advert_int = self.advert_int;

        let mut vip_addresses: Vec<Ipv4Addr> = Vec::new();
        vip_addresses.push(self.virtual_ip.0);

        pkt_hdr.set_vip_addresses(&vip_addresses);

        // TODO
        let auth_data = [49, 49, 49, 49, 0, 0, 0, 0].to_vec();

        pkt_hdr.set_auth_data(&auth_data);

        pkt_hdr.to_bytes()
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

fn start_advert_timer(advert_int: u8, sock_fd: i32, pkt_vec: Vec<u8>) -> Sender<TimerEvent> {
    let (tx, rx) = channel::<TimerEvent>(size_of::<TimerEvent>());
    tokio::task::spawn(async move { advert_timer(advert_int, sock_fd, pkt_vec, rx).await });

    tx
}

async fn advert_timer(interval: u8, sock_fd: i32, pkt_vec: Vec<u8>, mut rx: Receiver<TimerEvent>) {
    let mut timer_int = interval.clone();
    loop {
        debug!("starting advertisement timer!");

        let sleep = tokio::time::sleep(Duration::from_secs(timer_int as u64));
        tokio::pin!(sleep);

        tokio::select! {
            res = rx.recv() => {
                match res {
                    Some(event) => {
                        match event {
                            TimerEvent::ResetTimer => {
                                debug!("resetting master down timer..");
                            }
                            TimerEvent::ResetInterval(int) => {
                                debug!("resetting master down timer interval..");
                                timer_int = int as u8;
                            }
                            TimerEvent::Abort => {
                                debug!("aborting master down timer..");
                                break;
                            }
                        }
                    },
                    None => {},
                }
            },
            () = &mut sleep => {
                send_advertisement(sock_fd, pkt_vec.clone());
            }
        }
    }
}

fn start_master_down_timer(interval: f32, router_tx: Sender<Event>) -> Sender<TimerEvent> {
    let (tx, rx) = channel::<TimerEvent>(size_of::<TimerEvent>());
    tokio::task::spawn(async move { master_down_timer(interval, router_tx, rx).await });

    tx
}

async fn master_down_timer(interval: f32, tx: Sender<Event>, mut rx: Receiver<TimerEvent>) {
    let mut timer_int = interval.clone();
    loop {
        debug!("starting master down timer!");

        let sleep = tokio::time::sleep(Duration::from_millis((timer_int * 1000 as f32) as u64));
        tokio::pin!(sleep);

        tokio::select! {
            Some(event) = rx.recv() => {
                match event {
                    TimerEvent::ResetTimer => {
                        debug!("resetting master down timer..");
                    }
                    TimerEvent::ResetInterval(int) => {
                        debug!("resetting master down timer interval..");
                        timer_int = int;
                    }
                    TimerEvent::Abort => {
                        debug!("aborting master down timer..");
                        break;
                    }
                }
            },
            () = &mut sleep => {
                warn!("Master Unhealthy");
                _ = tx.send(Event::MasterDown).await;
                break;
            },
        };
    }
}
