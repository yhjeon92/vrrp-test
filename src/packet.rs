use std::{convert::TryInto, net::Ipv4Addr};

use serde::Deserialize;

use crate::constants::{
    ETH_PROTO_ARP, ETH_PROTO_IP, HW_TYPE_ETH, SOCKET_TTL, VIRTUAL_ROUTER_MAC, VRRP_MCAST_ADDR,
};

// RFC 826
pub struct GarpPacket {
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

impl GarpPacket {
    pub fn new(virtual_ip: Ipv4Addr, router_id: u8) -> GarpPacket {
        let mut packet = GarpPacket {
            mac_dst: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            mac_src: VIRTUAL_ROUTER_MAC,
            eth_proto: ETH_PROTO_ARP as u16,
            hw_type: HW_TYPE_ETH,
            proto_type: ETH_PROTO_IP as u16,
            hw_len: 6,
            proto_len: 4,
            op_code: 1,
            hw_addr_src: VIRTUAL_ROUTER_MAC,
            proto_addr_src: virtual_ip.octets(),
            hw_addr_dst: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            proto_addr_dst: virtual_ip.octets(),
        };

        packet.mac_src[5] = router_id;
        packet.hw_addr_src[5] = router_id;

        packet
    }

    pub fn to_bytes(&mut self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();

        bytes.extend_from_slice(&self.mac_dst);
        bytes.extend_from_slice(&self.mac_src);

        bytes.extend_from_slice(&self.eth_proto.to_be_bytes());
        bytes.extend_from_slice(&self.hw_type.to_be_bytes());
        bytes.extend_from_slice(&self.proto_type.to_be_bytes());
        bytes.push(self.hw_len);
        bytes.push(self.proto_len);
        bytes.extend_from_slice(&self.op_code.to_be_bytes());
        bytes.extend_from_slice(&self.hw_addr_src);
        bytes.extend_from_slice(&self.proto_addr_src);
        bytes.extend_from_slice(&self.hw_addr_dst);
        bytes.extend_from_slice(&self.proto_addr_dst);

        return bytes;
    }
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
    pub ip_src: [u8; 4],
    pub ip_dst: [u8; 4],

    // VRRPV2 Packet Fields
    // Version (4-bits; 2 for vrrpv2, 3 for vrrpv3) + Type (4-bits; vrrp advertisement must be represented by 1)
    pub ver_type: u8,
    pub router_id: u8,
    pub priority: u8,
    pub cnt_ip_addr: u8,
    pub auth_type: u8,
    pub advert_int: u8,
    pub checksum: u16,

    #[serde(skip_deserializing)]
    pub vip_addresses: Vec<Ipv4Addr>,
    #[serde(skip_deserializing)]
    pub auth_data: Vec<u8>,
}

impl VrrpV2Packet {
    pub fn new() -> VrrpV2Packet {
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
            ip_dst: VRRP_MCAST_ADDR.octets(),
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

    pub fn set_vip_addresses(&mut self, addresses: &Vec<Ipv4Addr>) {
        self.vip_addresses = addresses.clone();
    }

    pub fn set_auth_data(&mut self, auth_data: &Vec<u8>) {
        self.auth_data = auth_data.clone();
    }

    pub fn print(&self) {
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

    pub fn to_bytes(&mut self) -> Vec<u8> {
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

    pub fn verify_checksum(&self) -> Result<(), String> {
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

    pub fn calculate_checksum(&mut self) -> Result<(), String> {
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
