use std::{convert::TryInto, net::Ipv4Addr};

use serde::Deserialize;

use crate::constants::{
    ETH_PROTO_ARP, ETH_PROTO_IP, HW_TYPE_ETH, IPPROTO_VRRPV2, SOCKET_TTL, VIRTUAL_ROUTER_MAC,
    VRRP_MCAST_ADDR,
};

// Size 8
pub struct IfAddrMessage {
    ifa_family: u8,
    ifa_prefixlen: u8,
    ifa_flags: u8,
    ifa_scope: u8,
    ifa_index: u32,
}

impl IfAddrMessage {
    pub fn new(family: u8, prefix_len: u8, flags: u8, scope: u8, index: u32) -> IfAddrMessage {
        IfAddrMessage {
            ifa_family: family,
            ifa_prefixlen: prefix_len,
            ifa_flags: flags,
            ifa_scope: scope,
            ifa_index: index,
        }
    }

    pub fn to_bytes(&mut self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();

        bytes.push(self.ifa_family);
        bytes.push(self.ifa_prefixlen);
        bytes.push(self.ifa_flags);
        bytes.push(self.ifa_scope);
        bytes.extend_from_slice(&self.ifa_index.to_ne_bytes());

        bytes
    }
}

// Hdr Size 16
/*
    <----------- nlmsg_total_size(len) ------------>
    <----------- nlmsg_size(len) ------------>

   +-------------------+- - -+- - - - - - - - +- - -+-------------------+- - -
   |  struct nlmsghdr  | Pad |     Payload    | Pad |  struct nlsmghdr  |
   +-------------------+- - -+- - - - - - - - +- - -+-------------------+- - -

    <---- NLMSG_HDRLEN -----> <- NLMSG_ALIGN(len) -> <---- NLMSG_HDRLEN ---
*/
pub struct NetLinkMessage {
    msg_len: u32,
    msg_type: u16,
    msg_flags: u16,
    msg_seq: u32,
    msg_pid: u32,
    attributes: Vec<NetLinkAttribute>,
}

// Hdr Size 4
/*
     <----------- nla_total_size(payload) ----------->
     <---------- nla_size(payload) ----------->

    +-----------------+- - -+- - - - - - - - - +- - -+-----------------+- - -
    |  struct nlattr  | Pad |     Payload      | Pad |  struct nlattr  |
    +-----------------+- - -+- - - - - - - - - +- - -+-----------------+- - -

     <---- NLA_HDRLEN -----> <--- NLA_ALIGN(len) ---> <---- NLA_HDRLEN ---
*/
pub struct NetLinkAttribute {
    nla_len: u16,
    nla_type: u16,
    nla_data: Vec<u8>,
}

impl NetLinkAttribute {
    pub fn new(nla_len: u16, nla_type: u16, mut nla_data: Vec<u8>) -> NetLinkAttribute {
        let pad_len = ((nla_data.len() + 4 - 1) & !(4 - 1)) - nla_data.len();
        for _ in 0..pad_len {
            nla_data.push(0u8);
        }
        NetLinkAttribute {
            nla_len,
            nla_type,
            nla_data,
        }
    }
}

impl NetLinkMessage {
    pub fn new(
        msg_len: u32,
        msg_type: u16,
        msg_flags: u16,
        msg_seq: u32,
        msg_pid: u32,
    ) -> NetLinkMessage {
        NetLinkMessage {
            msg_len,
            msg_type,
            msg_flags,
            msg_seq,
            msg_pid,
            attributes: Vec::<NetLinkAttribute>::new(),
        }
    }

    pub fn add_attribute(&mut self, nla_len: u16, nla_type: u16, nla_data: Vec<u8>) {
        _ = &self
            .attributes
            .push(NetLinkAttribute::new(nla_len, nla_type, nla_data));
    }

    pub fn to_bytes(&mut self, payload: &mut Vec<u8>) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();

        // self.msg_len = (16 + payload.len()) as u32;

        // Netlink message must be padded to have the length multiple of NLMSG_ALIGNTO, which is fixed to 4 bytes.
        let data_len = (16 + payload.len()) as u32;
        let pad_len = ((data_len + 4 - 1) & !(4 - 1)) - data_len;
        self.msg_len = data_len + pad_len;

        println!("data_len {}, pad_len {}", data_len, pad_len);

        let mut attr_bytes: Vec<u8> = Vec::new();

        for attribute in self.attributes.iter_mut() {
            attr_bytes.extend_from_slice(&attribute.nla_len.to_le_bytes());
            attr_bytes.extend_from_slice(&attribute.nla_type.to_le_bytes());
            attr_bytes.append(&mut attribute.nla_data);
            self.msg_len += (attribute.nla_data.len() + 4) as u32;
        }

        bytes.extend_from_slice(&self.msg_len.to_le_bytes());
        bytes.extend_from_slice(&self.msg_type.to_le_bytes());
        bytes.extend_from_slice(&self.msg_flags.to_le_bytes());
        bytes.extend_from_slice(&self.msg_seq.to_le_bytes());
        bytes.extend_from_slice(&self.msg_pid.to_le_bytes());

        for _ in 0..pad_len {
            bytes.push(0u8);
        }

        bytes.append(payload);

        bytes.append(&mut attr_bytes);

        bytes
    }
}

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
    _ip_ver: u8,
    _ip_dscp: u8,
    _ip_length: u16,
    _ip_id: u16,
    _ip_flags: u16,
    ip_ttl: u8,
    _ip_proto: u8,
    _ip_checksum: u16,
    pub ip_src: [u8; 4],
    pub _ip_dst: [u8; 4],

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
            _ip_ver: 0x45,
            _ip_dscp: 0xC0,
            _ip_length: 0,
            _ip_id: 0,
            _ip_flags: 0,
            ip_ttl: SOCKET_TTL,
            _ip_proto: IPPROTO_VRRPV2 as u8,
            _ip_checksum: 0,
            ip_src: [0, 0, 0, 0],
            _ip_dst: VRRP_MCAST_ADDR.octets(),
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

        bytes.extend_from_slice(&self.checksum.to_be_bytes());

        for address in self.vip_addresses.clone().into_iter() {
            bytes.extend_from_slice(&address.octets());
        }

        bytes.extend_from_slice(&self.auth_data);

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
