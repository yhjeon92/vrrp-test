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
    socket::{send_advertisement, send_gratuitous_arp},
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
    auth_type: u8,
    master_down_int: f32,
    skew_time: f32,
    preempt_mode: bool,
    pre_promote_script: Option<String>,
    pre_demote_script: Option<String>,
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
            // TODO: backward compatibility
            auth_type: 1,
            master_down_int: (3 as f32 * config.advert_int as f32)
                + ((256 as u16 - config.priority as u16) as f32 / 256 as f32),
            skew_time: ((256 as u16 - config.priority as u16) as f32 / 256 as f32),
            preempt_mode: true,
            pre_promote_script: config.pre_promote_script,
            pre_demote_script: config.pre_demote_script,
            vip_addresses: config.vip_addresses,
            // TODO
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
                                        match send_advertisement(
                                            self.sock_fd.as_raw_fd(),
                                            advert_pkt.clone(),
                                        ) {
                                            Ok(_) => {}
                                            Err(err) => {
                                                warn!("Failed to send VRRP advertisement: {}", err);
                                            }
                                        }

                                        match &self.pre_promote_script {
                                            Some(command) => {
                                                _ = execute_command(command.to_owned());
                                            }
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
                                                    error!(
                                                        "Failed to send gratuitous ARP request: {}",
                                                        err
                                                    );
                                                    error!("exiting...");
                                                    return;
                                                }
                                            }

                                            // Add virtual ip address to interface
                                            match add_ip_address(&self.if_name, virtual_ip) {
                                                Ok(_) => {}
                                                Err(err) => {
                                                    error!("Failed to add IP address {} to interface {}: {}",
                                                    virtual_ip, &self.if_name, err);
                                                    error!("exiting...");
                                                    return;
                                                }
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
                                                        .send(TimerEvent::ResetInterval(
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
                                                                .send(TimerEvent::ResetTimer)
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
                                            match send_advertisement(
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
                                                        .send(TimerEvent::ResetInterval(
                                                            self.advert_int as f32,
                                                        ))
                                                        .await;
                                                }
                                                None => { /* */ }
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

                                            match &self.pre_demote_script {
                                                Some(command) => {
                                                    _ = execute_command(command.to_owned());
                                                }
                                                None => {}
                                            }

                                            for virtual_ip in self.vip_addresses.iter() {
                                                // Delete virtual ip bound to interface
                                                match del_ip_address(&self.if_name, virtual_ip) {
                                                    Ok(_) => {}
                                                    Err(err) => {
                                                        error!("Failed to delete IP address {} from interface {}: {}", virtual_ip, &self.if_name, err);
                                                        error!("exiting..");
                                                        return;
                                                    }
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
                                match send_advertisement(
                                    self.sock_fd.as_raw_fd(),
                                    advert_pkt.clone(),
                                ) {
                                    Ok(_) => {}
                                    Err(err) => {
                                        warn!("Failed to send VRRP advertisement: {}", err);
                                    }
                                }

                                match &self.pre_promote_script {
                                    Some(command) => {
                                        _ = execute_command(command.to_owned());
                                    }
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
                                            error!(
                                                "Failed to send gratuitous ARP request: {}",
                                                err
                                            );
                                            error!("exiting...");
                                            return;
                                        }
                                    }

                                    // Add virtual ip address to interface
                                    match add_ip_address(&self.if_name, virtual_ip) {
                                        Ok(_) => {}
                                        Err(err) => {
                                            error!(
                                                "Failed to add IP address {} to interface {}: {}",
                                                virtual_ip, &self.if_name, err
                                            );
                                            error!("exiting...");
                                            return;
                                        }
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
                                    None => {
                                        warn!("No reference to the Master Down timer was found. Skip stopping the timer..");
                                    }
                                };

                                self.state = State::Master;
                            }
                            _ => {
                                // TODO
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

                                match &self.pre_demote_script {
                                    Some(command) => {
                                        _ = execute_command(command.to_owned());
                                    }
                                    None => {}
                                }

                                for virtual_ip in self.vip_addresses.iter() {
                                    // Delete virtual ip bound to interface
                                    match del_ip_address(&self.if_name, virtual_ip) {
                                        Ok(_) => {}
                                        Err(err) => {
                                            error!("Failed to delete IP address {} from interface {}: {}", virtual_ip, &self.if_name, err);
                                            error!("exiting..");
                                            return;
                                        }
                                    }
                                }

                                let elect_pkt = VrrpV2Packet::build(
                                    self.router_id,
                                    0, /* Priority of 0 indicates Master stopped participating in VRRP */
                                    self.auth_type,
                                    self.advert_int,
                                    Vec::<Ipv4Addr>::from(
                                        self.vip_addresses
                                            .iter()
                                            .map(|addr| addr.address)
                                            .collect::<Vec<Ipv4Addr>>(),
                                    ),
                                    self.auth_data.clone(),
                                );

                                match send_advertisement(self.sock_fd.as_raw_fd(), elect_pkt) {
                                    Ok(_) => {}
                                    Err(err) => {
                                        warn!("Failed to send VRRP advertisement: {}", err);
                                    }
                                }

                                self.state = State::Initialize;
                            }
                            State::Initialize => {
                                info!("Termination signal received. Exiting..");
                                std::process::exit(0);
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
}

fn start_advert_timer(advert_int: u8, sock_fd: i32, vrrp_pkt: VrrpV2Packet) -> Sender<TimerEvent> {
    let (tx, rx) = channel::<TimerEvent>(3);
    tokio::task::spawn(async move { advert_timer(advert_int, sock_fd, vrrp_pkt, rx).await });

    tx
}

async fn advert_timer(
    interval: u8,
    sock_fd: i32,
    vrrp_pkt: VrrpV2Packet,
    mut rx: Receiver<TimerEvent>,
) {
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

fn start_master_down_timer(interval: f32, router_tx: Sender<Event>) -> Sender<TimerEvent> {
    let (tx, rx) = channel::<TimerEvent>(1);
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

fn execute_command(command: String) -> Result<(), String> {
    let mut elements = command.split_whitespace();

    match elements.next() {
        Some(program) => {
            let mut cmd = Command::new(program);
            elements.by_ref().for_each(|arg| {
                cmd.arg(arg);
            });

            match cmd.output() {
                Ok(output) => {
                    match output.status.code().unwrap() {
                        0 => {
                            info!(
                                "Command {} returned {} with status code 0",
                                command,
                                String::from_utf8(output.stdout).unwrap().trim_end()
                            );
                        }
                        code => {
                            warn!(
                                "Command {} failed with status code {}: {}",
                                command,
                                code,
                                String::from_utf8(output.stderr).unwrap().trim_end()
                            );
                        }
                    }

                    Ok(())
                }
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
