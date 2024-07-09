use arc_swap::ArcSwap;
use bincode::Options;
use once_cell::sync::Lazy;
use packet::VrrpV2Packet;
use router::{Event, Router};
use socket::{open_advertisement_socket, open_arp_socket};
use std::{
    convert::TryInto,
    fs::File,
    io::Read,
    mem,
    net::Ipv4Addr,
    os::fd::{AsRawFd, OwnedFd},
    sync::Arc,
    thread,
};
use tokio::sync::mpsc;
mod constants;
mod packet;
mod router;
mod socket;

use clap::Parser;
use nix::sys::socket::{recvfrom, SockaddrIn};
use serde::{Deserialize, Serialize};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    /// Name of network interface, defaults to lo. Required for Read Only mode (without -r flag) only.
    #[arg(short, default_value_t = String::from("eth0"))]
    interface: String,
    /// Option to run in Virtual Router mode, defaults to false. Multicast advertise packet if set, otherwise just print received VRRPv2 packet on the specified interface.
    #[arg(short, default_value_t = false)]
    router: bool,
    /// Path to the virtual router config file, defaults to vrrp.toml in working dir. Required for Virtual Router mode only.
    #[arg(short, default_value_t = String::from("vrrp.toml"))]
    config_file_path: String,
}

#[derive(Serialize, Deserialize)]
struct Config {
    interface: String,
    router_id: u8,
    priority: u8,
    advert_int: u8,
    virtual_ip: Ipv4Addr,
}

impl Config {
    fn dummy() -> Config {
        Config {
            interface: String::new(),
            router_id: 0,
            priority: 0,
            advert_int: 255,
            virtual_ip: Ipv4Addr::new(0, 0, 0, 0),
        }
    }
}

#[repr(C)]
struct IOctlFlags {
    ifr_name: [u8; 16],
    ifr_flags: i16,
}

static CONFIG: Lazy<ArcSwap<Config>> = Lazy::new(|| ArcSwap::from_pointee(Config::dummy()));

fn main() {
    let args = Args::parse();

    match args.router {
        true => {
            let mut contents = String::new();
            let mut file = match File::open(args.config_file_path) {
                Ok(file) => file,
                Err(err) => {
                    println!("[ERROR] while opening config file: {}", err.to_string());
                    return;
                }
            };

            match file.read_to_string(&mut contents) {
                Ok(_) => (),
                Err(err) => {
                    println!("[ERROR] while reading config file: {}", err.to_string());
                    return;
                }
            };

            match toml::from_str::<Config>(&contents) {
                Ok(config) => {
                    println!("Interface  {}", config.interface);
                    println!("Router Id  {}", config.router_id);
                    println!("Priority   {}", config.priority);
                    println!("Interval   {}", config.advert_int);
                    println!("Virtual IP {}", config.virtual_ip.to_string());
                    CONFIG.store(Arc::new(config));
                }
                Err(err) => {
                    println!(
                        "[ERROR] while parsing configuration file: {}",
                        err.to_string()
                    );
                    return;
                }
            }
        }
        false => (),
    };

    let if_name = match args.router {
        true => CONFIG.load_full().interface.clone(),
        false => match args.interface.is_empty() {
            true => {
                println!("[ERROR] Network interface name must be specified with -i flag in Readonly mode");
                return;
            }
            false => args.interface,
        },
    };

    let sock_fd = match open_advertisement_socket(&if_name) {
        Ok(fd) => fd,
        Err(err) => {
            println!("[ERROR] while opening socket: {}", err.to_string());
            return;
        }
    };

    println!("Listening for vRRPv2 packets... {}", sock_fd.as_raw_fd());

    let mut pkt_buf: [u8; 1024] = [0; 1024];

    // Router Mode
    if args.router {
        let (tx, rx) = mpsc::channel::<Event>(mem::size_of::<Event>());

        let arp_sock_fd = match open_arp_socket(&if_name) {
            Ok(fd) => fd,
            Err(err) => {
                println!("[ERROR] while opening arp socket: {}", err.to_string());
                return;
            }
        };

        let mut router = match Router::new(
            if_name,
            match sock_fd.try_clone() {
                Ok(cloned_fd) => cloned_fd,
                Err(err) => {
                    println!(
                        "[ERROR] Cloning fd {} failed: {}",
                        sock_fd.as_raw_fd(),
                        err.to_string()
                    );
                    return;
                }
            },
            arp_sock_fd,
            tx.clone(),
            rx,
        ) {
            Ok(router) => router,
            Err(err) => {
                println!("[ERROR] failed to initialize a router: {}", err);
                return;
            }
        };

        thread::spawn(move || {
            router.start();
        });

        _ = tx.blocking_send(Event::Startup);

        loop {
            let vrrp_pkt: VrrpV2Packet = match recv_vrrp_packet(&sock_fd, &mut pkt_buf) {
                Ok(pkt) => pkt,
                Err(err) => {
                    println!("[ERROR] {}", err.to_string());
                    continue;
                }
            };

            let router_id = vrrp_pkt.router_id;
            let priority = vrrp_pkt.priority;
            let src_addr = vrrp_pkt.ip_src.clone();

            match vrrp_pkt.verify_checksum() {
                Ok(_) => {
                    // vrrp_pkt.print();

                    match tx.blocking_send(Event::AdvertReceived(
                        router_id,
                        priority,
                        Ipv4Addr::from(src_addr),
                    )) {
                        Ok(_) => (),
                        Err(err) => {
                            println!("[ERROR], {}", err.to_string());
                        }
                    };
                }
                Err(err) => {
                    println!("[ERROR] {}", err);
                }
            }
        }
    } else {
        // Read Only Mode
        loop {
            let vrrp_pkt = match recv_vrrp_packet(&sock_fd, &mut pkt_buf) {
                Ok(pkt) => pkt,
                Err(err) => {
                    println!("[ERROR] {}", err.to_string());
                    continue;
                }
            };

            match vrrp_pkt.verify_checksum() {
                Ok(_) => {
                    vrrp_pkt.print();
                }
                Err(err) => {
                    println!("[ERROR] {}", err);
                }
            }
        }
    }
}

fn recv_vrrp_packet(sock_fd: &OwnedFd, pkt_buf: &mut [u8]) -> Result<VrrpV2Packet, String> {
    let len = match recvfrom::<SockaddrIn>(sock_fd.as_raw_fd(), pkt_buf) {
        Ok((pkt_len, sender_addr)) => {
            println!("Message of len {}", pkt_len);
            match sender_addr {
                Some(addr) => {
                    println!("Sender Address {}", addr.ip().to_string());
                }
                None => {}
            };
            pkt_len
        }
        Err(err) => {
            return Err(format!("[ERROR] {}", err.to_string()));
        }
    };

    // bincode::deserialize와 bincode::Options::deserialize의 동작이 다르므로 fixint encoding으로 변경함
    let mut vrrp_pkt: VrrpV2Packet = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_big_endian()
        .deserialize(&pkt_buf[0..28])
        .unwrap();

    for ind in 0..len {
        print!("{:02X?} ", pkt_buf[ind as usize]);
    }
    print!("\n");

    let mut vip_addresses: Vec<Ipv4Addr> = Vec::new();

    for ind in 0..vrrp_pkt.cnt_ip_addr {
        vip_addresses.push(Ipv4Addr::from(u32::from_be_bytes(
            pkt_buf[(28 + ind * 4) as usize..(32 + ind * 4) as usize]
                .try_into()
                .unwrap(),
        )));
    }

    vrrp_pkt.set_vip_addresses(&vip_addresses);

    let auth_data = pkt_buf[(28 + vrrp_pkt.cnt_ip_addr * 4) as usize..len as usize].to_vec();

    vrrp_pkt.set_auth_data(&auth_data);

    return Ok(vrrp_pkt);
}
