use arc_swap::ArcSwap;
use bincode::Options;
use once_cell::sync::Lazy;
use router::Router;
use std::{
    convert::TryInto,
    fs::File,
    io::Read,
    net::Ipv4Addr,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::Arc,
    thread,
};
mod constants;
mod router;
use clap::Parser;
use constants::{
    AF_INET, AF_PACKET, ETH_P_ARP, IFR_FLAG_MULTICAST, IFR_FLAG_RUNNING, IFR_FLAG_UP,
    IPPROTO_VRRPV2, SOCKET_TTL, SOCK_RAW,
};
use nix::{
    libc::socket,
    sys::socket::{bind, recvfrom, setsockopt, sockopt, IpMembershipRequest, SockaddrIn},
};
use serde::{Deserialize, Serialize};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    /// Name of network interface, defaults to lo. Required for Read Only mode (without -r flag) only.
    #[arg(short, default_value_t = String::new())]
    interface: String,
    /// Option to run in Virtual Router mode, defaults to false. Multicast advertise packet if set, otherwise just print received VRRPv2 packet on the specified interface.
    #[arg(short, default_value_t = false)]
    router: bool,
    /// Path to the virtual router config file, defaults to vrrp-test.toml in working dir. Required for Virtual Router mode only.
    #[arg(short, default_value_t = String::from("vrrp-test.toml"))]
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

// RFC 826
struct ArpPacket {
    mac_dst: [u8; 6],
    mac_src: [u8; 6],
    eth_proto: u16,

    hw_type: u16,
    proto_type: u16,
    hw_len: u8,    // 6?
    proto_len: u8, // 4?
    op_code: u16,
    hw_addr_src: [u8; 6],
    proto_addr_src: [u8; 4],
    hw_addr_dst: [u8; 6],
    proto_addr_dst: [u8; 4],
}

#[derive(Deserialize, Debug)]
pub struct VrrpV2Packet {
    // IPv4 Header Fields
    ip_ver: u8,
    ip_dscp: u8,
    ip_length: u16,
    ip_id: u16,
    ip_flags: u16,
    ip_ttl: u8,
    ip_proto: u8,
    ip_checksum: u16,
    ip_src: [u8; 4],
    ip_dst: [u8; 4],

    // VRRPV2 Packet Fields
    // Version (4-bits; 2 for vrrpv2, 3 for vrrpv3) + Type (4-bits; vrrp advertisement must be represented by 1)
    ver_type: u8,
    router_id: u8,
    priority: u8,
    cnt_ip_addr: u8,
    auth_type: u8,
    advert_int: u8,
    checksum: u16,

    #[serde(skip_deserializing)]
    vip_addresses: Vec<Ipv4Addr>,
    #[serde(skip_deserializing)]
    auth_data: Vec<u8>,
}

impl VrrpV2Packet {
    fn new() -> VrrpV2Packet {
        VrrpV2Packet {
            ip_ver: 0x45,
            ip_dscp: 0xC0,
            ip_length: 0,
            ip_id: 0,
            ip_flags: 0,
            ip_ttl: SOCKET_TTL,
            ip_proto: 0x70,
            ip_checksum: 0,
            ip_src: [0, 0, 0, 0],
            ip_dst: [224, 0, 0, 18],
            ver_type: 0x21,
            router_id: 0,
            priority: 0,
            cnt_ip_addr: 0,
            auth_type: 0,
            advert_int: 0,
            checksum: 0,
            vip_addresses: Vec::new(),
            auth_data: Vec::new(),
        }
    }

    fn set_vip_addresses(&mut self, addresses: &Vec<Ipv4Addr>) {
        self.vip_addresses = addresses.clone();
    }

    fn set_auth_data(&mut self, auth_data: &Vec<u8>) {
        self.auth_data = auth_data.clone();
    }

    fn print(&self) {
        println!("\tVRRP Ver:  {}", self.ver_type >> 4);
        println!("\tVRRP Type: {}", self.ver_type & 0xF);
        println!("\tSource:    {}", Ipv4Addr::from(self.ip_src));
        println!("\tRouterId:  {}", self.router_id);
        println!("\tPriority:  {}", self.priority);
        println!("\tAuthType:  {}", self.auth_type);
        println!("\tInterval:  {}", self.advert_int);
        println!("\tVIP count: {}", self.cnt_ip_addr);
        for ind in 0..self.vip_addresses.len() {
            println!("\t\t{}", self.vip_addresses[ind].to_string());
        }
        println!(
            "\tAuthData:  {}",
            String::from_utf8_lossy(self.auth_data.as_slice())
        );
    }

    fn to_bytes(&mut self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();
        match self.calculate_checksum() {
            Ok(_) => {}
            Err(err) => {
                println!("[ERROR] {}", err.to_string());
                return Vec::new();
            }
        }

        bytes.push(self.ver_type);
        bytes.push(self.router_id);
        bytes.push(self.priority);
        bytes.push(self.cnt_ip_addr);
        bytes.push(self.auth_type);
        bytes.push(self.advert_int);

        bytes.push((self.checksum >> 8) as u8);
        bytes.push(self.checksum as u8);

        for address in self.vip_addresses.clone().into_iter() {
            for address_byte in address.octets() {
                bytes.push(address_byte);
            }
        }

        for auth_data_byte in self.auth_data.clone().into_iter() {
            bytes.push(auth_data_byte);
        }

        return bytes;
    }

    fn verify_checksum(&self) -> Result<(), String> {
        if self.ip_ttl != 0xFF {
            return Err(format!("Packet TTL {} is not valid", self.ip_ttl));
        }

        if self.ver_type >> 4 != 2 {
            return Err(format!(
                "VRRP protocol version {} is not supported",
                self.ver_type >> 4
            ));
        }

        let mut sum: u32 = 0;

        // VRRPv2 Packet Checksum
        sum += u16::from_be_bytes([self.ver_type, self.router_id]) as u32;
        sum += u16::from_be_bytes([self.priority, self.cnt_ip_addr]) as u32;
        sum += u16::from_be_bytes([self.auth_type, self.advert_int]) as u32;

        for (_, address) in self.vip_addresses.iter().enumerate() {
            let address_bytes = address.octets();
            sum += u16::from_be_bytes(address_bytes[0..2].try_into().unwrap()) as u32;
            sum += u16::from_be_bytes(address_bytes[2..4].try_into().unwrap()) as u32;
        }

        let mut ind = 0;

        while ind < self.auth_data.len() {
            sum += u16::from_be_bytes(self.auth_data[ind..ind + 2].try_into().unwrap()) as u32;
            ind += 2;
        }

        sum += self.checksum as u32;

        sum = (sum & 0xFFFF) + (sum >> 16);

        if sum != 0xFFFF {
            return Err(format!("Failed to verify VRRPv2 packet checksum"));
        }

        return Ok(());
    }

    fn calculate_checksum(&mut self) -> Result<(), String> {
        let mut sum: u32 = 0;

        sum += u16::from_be_bytes([self.ver_type, self.router_id]) as u32;
        sum += u16::from_be_bytes([self.priority, self.cnt_ip_addr]) as u32;
        sum += u16::from_be_bytes([self.auth_type, self.advert_int]) as u32;

        for (_, address) in self.vip_addresses.iter().enumerate() {
            let address_bytes = address.octets();
            sum += u16::from_be_bytes(address_bytes[0..2].try_into().unwrap()) as u32;
            sum += u16::from_be_bytes(address_bytes[2..4].try_into().unwrap()) as u32;
        }

        let mut ind = 0;

        while ind < self.auth_data.len() {
            sum += u16::from_be_bytes(self.auth_data[ind..ind + 2].try_into().unwrap()) as u32;
            ind += 2;
        }

        self.checksum = !((sum & 0xFFFF) + (sum >> 16)) as u16;

        return Ok(());
    }
}

static CONFIG: Lazy<ArcSwap<Config>> = Lazy::new(|| ArcSwap::from_pointee(Config::dummy()));
static ADVERT: Lazy<ArcSwap<(bool, VrrpV2Packet)>> =
    Lazy::new(|| ArcSwap::from_pointee((false, VrrpV2Packet::new())));

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
        // true => CONFIG.load_full().interface.clone(),
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

    if args.router {
        let router = Router::new(match sock_fd.try_clone() {
            Ok(cloned_fd) => cloned_fd,
            Err(err) => {
                println!(
                    "[ERROR] Cloning fd {} failed: {}",
                    sock_fd.as_raw_fd(),
                    err.to_string()
                );
                return;
            }
        });

        thread::spawn(move || {
            router.start();
        });
    }

    let mut pkt_buf: [u8; 1024] = [0; 1024];

    loop {
        if args.router {
            // Router mode

            let vrrp_pkt = match recv_vrrp_packet(&sock_fd, &mut pkt_buf) {
                Ok(pkt) => pkt,
                Err(err) => {
                    println!("[ERROR] {}", err.to_string());
                    continue;
                }
            };

            match vrrp_pkt.verify_checksum() {
                Ok(_) => {
                    // vrrp_pkt.print();
                    ADVERT.store(Arc::new((true, vrrp_pkt)));
                }
                Err(err) => {
                    println!("[ERROR] {}", err);
                }
            }
        } else {
            // ReadOnly mode
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

pub fn open_advertisement_socket(if_name: &str) -> Result<OwnedFd, String> {
    let sock_fd: OwnedFd;

    unsafe {
        // AddressFamily AF_INET 0x02, SocketType SOCK_RAW 0x03, Protocol IPPROTO_VRRPV2 0x70 (112; vrrp)
        sock_fd = match socket(AF_INET, SOCK_RAW, IPPROTO_VRRPV2) {
            -1 => {
                return Err(format!(
                    "Failed to open a raw socket - check the process privileges"
                ));
            }
            fd => OwnedFd::from_raw_fd(fd),
        };
    }

    // if_nametoindex는 1-인덱싱, iter().nth()는 0-인덱싱
    let if_ind = match nix::net::if_::if_nametoindex(if_name) {
        Ok(ind) => ind - 1,
        Err(_) => {
            return Err(format!("No interface named {}", if_name));
        }
    };

    let interfaces = nix::net::if_::if_nameindex().unwrap();
    let interface = interfaces.iter().nth(if_ind as usize).unwrap();

    let ifname_slice = &mut [0u8; 16];

    for (i, b) in interface.name().to_bytes().iter().enumerate() {
        ifname_slice[i] = *b;
    }

    let mut if_opts = IOctlFlags {
        ifr_name: {
            let mut buf = [0u8; 16];
            buf.clone_from_slice(ifname_slice);
            buf
        },
        ifr_flags: 0,
    };

    unsafe {
        // UP (0x01), RUNNING (0x40), MULTICAST (0x1000)
        if_opts.ifr_flags |= IFR_FLAG_UP | IFR_FLAG_RUNNING | IFR_FLAG_MULTICAST;

        let res = nix::libc::ioctl(sock_fd.as_raw_fd(), nix::libc::SIOCSIFFLAGS, &mut if_opts);
        if res < 0 {
            println!("{}", std::io::Error::last_os_error().to_string());
            return Err(format!(
                "Cannot manipulate network interface {}",
                interface.name().to_string_lossy()
            ));
        }
    }

    match setsockopt(&sock_fd, sockopt::ReuseAddr, &true) {
        Ok(_) => {}
        Err(err) => {
            return Err(format!(
                "Error while applying ReuseAddr option for socket {}: {}",
                sock_fd.as_raw_fd().to_string(),
                err
            ));
        }
    }

    match setsockopt(&sock_fd, sockopt::IpMulticastTtl, &SOCKET_TTL) {
        Ok(_) => {}
        Err(err) => {
            return Err(format!(
                "Error while applying IPv4TTL option for socket {}: {}",
                sock_fd.as_raw_fd().to_string(),
                err
            ));
        }
    }

    let ip_mreq = IpMembershipRequest::new(
        Ipv4Addr::new(224, 0, 0, 18),
        Some(Ipv4Addr::new(0, 0, 0, 0)),
    );

    match setsockopt(&sock_fd, sockopt::IpAddMembership, &ip_mreq) {
        Ok(_) => {}
        Err(err) => {
            return Err(format!("Error while requesting IP Membership: {}", err));
        }
    }

    match bind(sock_fd.as_raw_fd(), &SockaddrIn::new(224, 0, 0, 18, 112)) {
        Ok(_) => {}
        Err(err) => {
            return Err(format!("Binding socket failed: {}", err));
        }
    }

    return Ok(sock_fd);
}

pub fn open_arp_socket() -> Result<OwnedFd, String> {
    let sock_fd: OwnedFd;

    unsafe {
        // AddressFamily AF_PACKET 0x11, SocketType SOCK_RAW 0x03, Protocol ETH_P_ARP 0x0806 (2054; arp)
        sock_fd = match socket(AF_PACKET, SOCK_RAW, ETH_P_ARP) {
            -1 => {
                return Err(format!(
                    "Failed to open a raw socket - check the process privileges"
                ));
            }
            fd => OwnedFd::from_raw_fd(fd),
        };
    }

    return Ok(sock_fd);
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
