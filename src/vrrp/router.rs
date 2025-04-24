use core::fmt;
use std::{
    collections::HashSet,
    net::Ipv4Addr,
    os::fd::{AsRawFd, OwnedFd},
    process::Command,
    time::Duration,
};

use log::{debug, error, info, warn};
use tokio::sync::mpsc::{channel, Receiver, Sender};

use crate::vrrp::{
    interface::{add_ip_address, del_ip_address, get_ip_address},
    packet::VrrpV2Packet,
    socket::{send_advertisement, send_advertisement_unicast, send_gratuitous_arp},
    Ipv4WithNetmask, VRouterConfig,
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
    ShutDown,
    MasterDown,
    // RouterId - Priority - Source - VIPs
    AdvertReceived(u8, u8, Ipv4Addr, Vec<Ipv4Addr>),
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Event::Startup => write!(f, "StartUp"),
            Event::MasterDown => write!(f, "MasterDown"),
            Event::AdvertReceived(rid, prior, src_addr, vips) => write!(
                f,
                "AdvertReceived rid {} prio {} addr {} vips {}",
                rid,
                prior,
                src_addr.to_string(),
                vips.iter()
                    .map(|addr| format!("{} ", addr.to_string()))
                    .collect::<String>()
            ),
            Event::ShutDown => write!(f, "ShutDown"),
        }
    }
}

enum TimerEvent {
    ResetTimerInterval(f32),
    Abort,
}

impl fmt::Display for TimerEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            TimerEvent::ResetTimerInterval(int) => {
                write!(f, "ResetTimerInterval {}s", int)
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
    auth_type: u8,
    master_down_int: f32,
    skew_time: f32,
    preempt_mode: bool,
    pre_promote_script: Option<String>,
    pre_demote_script: Option<String>,
    unicast_peers: Option<Vec<Ipv4Addr>>,
    vip_addresses: Vec<Ipv4WithNetmask>,
    auth_data: Vec<u8>,
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
            // for backward compatibility
            auth_type: 1,
            master_down_int: (3 as f32 * config.advert_int as f32)
                + ((256 as u16 - config.priority as u16) as f32 / 256 as f32),
            skew_time: ((256 as u16 - config.priority as u16) as f32 / 256 as f32),
            preempt_mode: true,
            pre_promote_script: config.pre_promote_script,
            pre_demote_script: config.pre_demote_script,
            unicast_peers: config.unicast_peers,
            vip_addresses: config.vip_addresses,
            // not in use since authenticating via auth_data field is discouraged
            auth_data: [].to_vec(),
            router_tx: tx,
            router_rx: rx,
        })
    }

    // RFC 3768 Protocol State Machine
    pub async fn start(&mut self) {
        info!("Router thread running...");

        let advert_pkt = VrrpV2Packet::build(
            self.router_id,
            self.priority,
            self.auth_type,
            self.advert_int,
            self.local_addr,
            Vec::<Ipv4Addr>::from(
                self.vip_addresses
                    .iter()
                    .map(|addr| addr.address)
                    .collect::<Vec<Ipv4Addr>>(),
            ),
            self.auth_data.clone(),
        );

        let elect_pkt = VrrpV2Packet::build(
            self.router_id,
            0, /* Priority of 0 indicates Master stopped participating in VRRP */
            self.auth_type,
            self.advert_int,
            self.local_addr,
            Vec::<Ipv4Addr>::from(
                self.vip_addresses
                    .iter()
                    .map(|addr| addr.address)
                    .collect::<Vec<Ipv4Addr>>(),
            ),
            self.auth_data.clone(),
        );

        info!("MASTER DOWN INTERVAL set to {}", self.master_down_int);

        let mut master_timer_tx: Option<Sender<TimerEvent>> = None;
        let mut advert_timer_tx: Option<Sender<TimerEvent>> = None;

        let configured_vips = self
            .vip_addresses
            .iter()
            .map(|address_netmask| address_netmask.address)
            .collect::<HashSet<_>>();

        // main router loop
        loop {
            match self.router_rx.recv().await {
                Some(event) => {
                    debug!("{}", event);

                    match event {
                        Event::Startup => {
                            match self.state {
                                State::Initialize => {
                                    // Do things..
                                    // Priority 255 -> preempting MASTER state
                                    if self.priority == 0xFF {
                                        // Promote oneself to Master
                                        info!("Promoting to MASTER state..");

                                        // Multicast Advertisement
                                        match self.send_vrrp_advert(
                                            self.sock_fd.as_raw_fd(),
                                            advert_pkt.clone(),
                                        ) {
                                            Ok(_) => {}
                                            Err(err) => {
                                                warn!("Failed to send VRRP advertisement: {}", err);
                                            }
                                        }

                                        match self.promote_to_master() {
                                            Ok(()) => {}
                                            Err(err) => {
                                                error!("Failed to initialize as master: {}", err);
                                                info!("Retrying initialization..");

                                                match self.router_tx.send(Event::Startup).await {
                                                    Ok(()) => {}
                                                    Err(err) => {
                                                        error!(
                                                            "Failed to re-initialize: {}",
                                                            err.to_string()
                                                        );
                                                    }
                                                }
                                                continue;
                                            }
                                        }

                                        // Start advertisement timer
                                        advert_timer_tx = Some(start_advert_timer(
                                            self.advert_int,
                                            self.sock_fd.as_raw_fd(),
                                            advert_pkt.clone(),
                                            self.unicast_peers.clone(),
                                        ));

                                        // Stop master down timer
                                        match master_timer_tx {
                                            Some(ref tx) => _ = tx.send(TimerEvent::Abort).await,
                                            None => { /*  */ }
                                        };

                                        self.state = State::Master;
                                    } else {
                                        // Promote oneself to BACKUP
                                        info!("Promoting to BACKUP state..");

                                        // Start master down timer
                                        master_timer_tx = Some(start_master_down_timer(
                                            self.master_down_int,
                                            self.router_tx.clone(),
                                        ));

                                        self.state = State::Backup;
                                    }
                                }
                                _ => (),
                            }
                        }
                        Event::AdvertReceived(router_id, priority, src_addr, vip_addresses) => {
                            match self.state {
                                State::Backup => {
                                    debug!(
                                        "\tAdvert router id {} - priority {} - src {}",
                                        router_id,
                                        priority,
                                        src_addr.to_string()
                                    );

                                    if router_id == self.router_id {
                                        if priority == 0 {
                                            /* MASTER stopped participating in VRRP */
                                            // Reset master down timer to skew_time
                                            warn!("VRRPv2 advert of priority 0 received.");
                                            match master_timer_tx {
                                                Some(ref tx) => {
                                                    _ = tx
                                                        .send(TimerEvent::ResetTimerInterval(
                                                            self.skew_time,
                                                        ))
                                                        .await
                                                }
                                                None => {
                                                    error!("cannot find master down timer binding, exiting..");
                                                    return;
                                                }
                                            };
                                        } else {
                                            if !self.preempt_mode || priority >= self.priority {
                                                if !vip_addresses
                                                    .into_iter()
                                                    .collect::<HashSet<_>>()
                                                    .eq(&configured_vips)
                                                {
                                                    warn!("Virtual IPs in received advert from {} does not match with local configuration", src_addr);
                                                } else {
                                                    // Master healthy. Resetting master down timer
                                                    match master_timer_tx {
                                                        Some(ref tx) => {
                                                            _ = tx
                                                                .send(TimerEvent::ResetTimerInterval(self.master_down_int))
                                                                .await
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
                                }
                                State::Master => {
                                    if router_id == self.router_id {
                                        if priority == 0 {
                                            // Send VRRPv2 advertisement
                                            match self.send_vrrp_advert(
                                                self.sock_fd.as_raw_fd(),
                                                advert_pkt.clone(),
                                            ) {
                                                Ok(_) => {}
                                                Err(err) => {
                                                    warn!(
                                                        "Failed to send VRRP advertisement: {}",
                                                        err
                                                    );
                                                }
                                            }
                                            // Set advert timer to advert_int
                                            match advert_timer_tx {
                                                Some(ref tx) => {
                                                    _ = tx
                                                        .send(TimerEvent::ResetTimerInterval(
                                                            self.advert_int as f32,
                                                        ))
                                                        .await;
                                                }
                                                None => { /* */ }
                                            }

                                            // Acquire virtual IP
                                            // This does not comply with RFC 3768 - additional safety measure for Cloud environment
                                            // where bare-metal ip link addr and arping is not sufficient to acquire Virtual IP
                                            match self.promote_to_master() {
                                                Ok(()) => {}
                                                Err(err) => {
                                                    error!("Failed to acquire virtual ip: {}", err);
                                                    warn!("Reset timer and remain as BACKUP..");

                                                    if let Some(ref tx) = advert_timer_tx {
                                                        _ = tx.send(TimerEvent::Abort).await;
                                                    }

                                                    master_timer_tx =
                                                        Some(start_master_down_timer(
                                                            self.master_down_int,
                                                            self.router_tx.clone(),
                                                        ));

                                                    self.state = State::Backup;

                                                    continue;
                                                }
                                            }

                                            // Received an Advert with higher priority - demoting to BACKUP
                                        } else if (!self.preempt_mode || priority > self.priority)
                                            || (priority == self.priority
                                                && src_addr > self.local_addr)
                                        {
                                            // Transition to Backup
                                            info!("Received VRRP advert from src {} with priority {}, higher than priority of local node {}",
                                                src_addr.to_string(),
                                                priority,
                                                self.priority);

                                            info!("Demoting to BACKUP state..");

                                            // Stop advert timer
                                            match advert_timer_tx {
                                                Some(ref tx) => {
                                                    _ = tx.send(TimerEvent::Abort).await
                                                }
                                                None => {
                                                    warn!("No reference to the Master Down timer was found. Skip stopping the timer..");
                                                }
                                            };

                                            advert_timer_tx = None;

                                            match self.demote_to_backup(&elect_pkt) {
                                                Ok(()) => {}
                                                Err(err) => {
                                                    warn!(
                                                        "Error while demoting to backup: {}",
                                                        err
                                                    );
                                                }
                                            }

                                            // Start master down timer
                                            master_timer_tx = Some(start_master_down_timer(
                                                self.master_down_int,
                                                self.router_tx.clone(),
                                            ));

                                            self.state = State::Backup;
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                        Event::MasterDown => match self.state {
                            State::Backup => {
                                warn!("Master down interval expired.");
                                info!("Promoting to MASTER state..");

                                // Multicast Advertisement
                                match self
                                    .send_vrrp_advert(self.sock_fd.as_raw_fd(), advert_pkt.clone())
                                {
                                    Ok(_) => {}
                                    Err(err) => {
                                        warn!("Failed to send VRRP advertisement: {}", err);
                                    }
                                }

                                match self.promote_to_master() {
                                    Ok(()) => {}
                                    Err(err) => {
                                        error!("Failed to promote: {}", err);
                                        warn!("Reset timer and remain as BACKUP..");

                                        master_timer_tx = Some(start_master_down_timer(
                                            self.master_down_int,
                                            self.router_tx.clone(),
                                        ));

                                        continue;
                                    }
                                }

                                // Start advertisement timer
                                advert_timer_tx = Some(start_advert_timer(
                                    self.advert_int,
                                    self.sock_fd.as_raw_fd(),
                                    advert_pkt.clone(),
                                    self.unicast_peers.clone(),
                                ));

                                // Stop master down timer
                                match master_timer_tx {
                                    Some(ref tx) => _ = tx.send(TimerEvent::Abort).await,
                                    None => {
                                        warn!("No reference to the Master Down timer was found. Skip stopping the timer..");
                                    }
                                };

                                self.state = State::Master;
                            }
                            _ => {
                                // No Action
                            }
                        },
                        Event::ShutDown => match self.state {
                            State::Backup => {
                                /* Shutting down BACKUP */
                                // Demote to initialize state
                                info!("Demoting to INITIALIZE state..");

                                // Stop master down timer
                                match master_timer_tx {
                                    Some(ref tx) => _ = tx.send(TimerEvent::Abort).await,
                                    None => {
                                        warn!("No reference to the Master Down timer was found. Skip stopping the timer..");
                                    }
                                };

                                self.state = State::Initialize;
                            }
                            State::Master => {
                                /* Shutting down MASTER */
                                // Demote to initialize state
                                info!("Demoting to INITIALIZE state..");

                                // Stop advert timer
                                match advert_timer_tx {
                                    Some(ref tx) => _ = tx.send(TimerEvent::Abort).await,
                                    None => {
                                        warn!("No reference to the Master Down timer was found. Skip stopping the timer..");
                                    }
                                };

                                match self.demote_to_backup(&elect_pkt) {
                                    Ok(()) => {}
                                    Err(err) => {
                                        warn!("Error while demoting to backup: {}", err);
                                    }
                                }

                                self.state = State::Initialize;
                            }
                            State::Initialize => {
                                info!("Termination signal received. Exiting..");
                                return;
                            }
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

    fn send_vrrp_advert(&mut self, sock_fd: i32, vrrp_pkt: VrrpV2Packet) -> Result<(), String> {
        match &self.unicast_peers {
            Some(peers) => return send_advertisement_unicast(sock_fd, vrrp_pkt, peers.clone()),
            None => return send_advertisement(sock_fd, vrrp_pkt),
        }
    }

    fn demote_to_backup(&mut self, elect_pkt: &VrrpV2Packet) -> Result<(), String> {
        match &self.pre_demote_script {
            Some(command) => match execute_command(command.to_owned()) {
                Ok(()) => {}
                Err(err) => {
                    return Err(format!(
                        "Failed to execute pre_demote script [{}]: {}",
                        command, err
                    ));
                }
            },
            None => {}
        }

        match self.send_vrrp_advert(self.sock_fd.as_raw_fd(), elect_pkt.clone()) {
            Ok(_) => {}
            Err(err) => {
                warn!("Failed to send VRRP election request: {}", err);
            }
        }

        for virtual_ip in self.vip_addresses.iter() {
            // Delete virtual ip bound to interface
            match del_ip_address(&self.if_name, virtual_ip) {
                Ok(_) => {}
                Err(err) => {
                    return Err(format!(
                        "Failed to delete IP address {} from interface {}: {}",
                        virtual_ip, &self.if_name, err
                    ));
                }
            }
        }

        Ok(())
    }

    fn promote_to_master(&mut self) -> Result<(), String> {
        match &self.pre_promote_script {
            Some(command) => match execute_command(command.to_owned()) {
                Ok(()) => {}
                Err(err) => {
                    return Err(format!(
                        "Failed to execute pre_promote script [{}]: {}",
                        command, err
                    ));
                }
            },
            None => {}
        }

        for virtual_ip in self.vip_addresses.iter() {
            // Broadcast Gratuitous ARP
            match send_gratuitous_arp(
                self.arp_sock_fd.as_raw_fd(),
                &self.if_name,
                self.router_id,
                virtual_ip,
            ) {
                Ok(_) => {}
                Err(err) => {
                    return Err(format!("Failed to send gratuitous ARP request: {}", err));
                }
            }

            // Add virtual ip address to interface
            match add_ip_address(&self.if_name, virtual_ip) {
                Ok(_) => {}
                Err(err) => {
                    return Err(format!(
                        "Failed to add IP address {} to interface {}: {}",
                        virtual_ip, &self.if_name, err
                    ))
                }
            }
        }

        Ok(())
    }
}

fn start_advert_timer(
    advert_int: u8,
    sock_fd: i32,
    vrrp_pkt: VrrpV2Packet,
    unicast_peers: Option<Vec<Ipv4Addr>>,
) -> Sender<TimerEvent> {
    let (tx, rx) = channel::<TimerEvent>(3);
    tokio::task::spawn(async move {
        advert_timer(advert_int, sock_fd, vrrp_pkt, unicast_peers, rx).await
    });

    tx
}

async fn advert_timer(
    interval: u8,
    sock_fd: i32,
    vrrp_pkt: VrrpV2Packet,
    unicast_peers: Option<Vec<Ipv4Addr>>,
    mut rx: Receiver<TimerEvent>,
) {
    let mut timer_int = interval.clone();
    loop {
        let sleep = tokio::time::sleep(Duration::from_secs(timer_int as u64));
        tokio::pin!(sleep);

        tokio::select! {
            Some(event) = rx.recv() => {
                match event {
                    TimerEvent::ResetTimerInterval(int) => {
                        info!("resetting advertisement timer interval..");
                        timer_int = int as u8;
                    }
                    TimerEvent::Abort => {
                        info!("aborting advertisement timer..");
                        break;
                    }
                }
            },
            () = &mut sleep => {
                match unicast_peers {
                    Some(ref peers) => {
                        match send_advertisement_unicast(sock_fd, vrrp_pkt.clone(), peers.clone()) {
                            Ok(_) => {}
                            Err(err) => {
                                warn!("Failed to send VRRP advertisement: {}", err);
                            }
                        }
                    },
                    None => {
                        match send_advertisement(sock_fd, vrrp_pkt.clone()) {
                            Ok(_) => {}
                            Err(err) => {
                                warn!("Failed to send VRRP advertisement: {}", err);
                            }
                        }
                    }
                }
            }
        }
    }
}

fn start_master_down_timer(interval: f32, router_tx: Sender<Event>) -> Sender<TimerEvent> {
    let (tx, rx) = channel::<TimerEvent>(1);
    tokio::task::spawn(async move { master_down_timer(interval, router_tx, rx).await });

    tx
}

async fn master_down_timer(interval: f32, tx: Sender<Event>, mut rx: Receiver<TimerEvent>) {
    let mut timer_int = interval.clone();
    loop {
        let sleep = tokio::time::sleep(Duration::from_millis((timer_int * 1000 as f32) as u64));
        tokio::pin!(sleep);

        tokio::select! {
            Some(event) = rx.recv() => {
                match event {
                    TimerEvent::ResetTimerInterval(int) => {
                        info!("resetting master down timer interval..");
                        timer_int = int;
                    }
                    TimerEvent::Abort => {
                        info!("aborting master down timer..");
                        break;
                    }
                }
            },
            () = &mut sleep => {
                warn!("Master Unhealthy");
                match tx.send(Event::MasterDown).await {
                    Ok(()) => {},
                    Err(err) => {
                        warn!("Failed to send router event: {}", err.to_string());
                    },
                }
                break;
            },
        };
    }
}

fn execute_command(command: String) -> Result<(), String> {
    let mut elements = command.split_whitespace();

    match elements.next() {
        Some(program) => {
            let mut cmd = Command::new(program);
            elements.by_ref().for_each(|arg| {
                cmd.arg(arg);
            });

            match cmd.output() {
                Ok(output) => match output.status.code().unwrap() {
                    0 => {
                        info!(
                            "Command {} returned {} with status code 0",
                            command,
                            String::from_utf8(output.stdout).unwrap().trim_end()
                        );
                        Ok(())
                    }
                    code => {
                        let err_msg = format!(
                            "{} {}",
                            String::from_utf8(output.stdout).unwrap().trim_end(),
                            String::from_utf8(output.stderr).unwrap().trim_end()
                        );
                        warn!(
                            "Command {} failed with status code {}: {}",
                            command, code, err_msg
                        );
                        Err(err_msg)
                    }
                },
                Err(err) => {
                    warn!("Command {} failed: {}", command, err.to_string());
                    Err(err.to_string())
                }
            }
        }
        None => {
            warn!(
                "Command {} seems to be empty. Check your configuration.",
                command
            );
            Ok(())
        }
    }
}
