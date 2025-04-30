use std::{convert::TryInto, mem::size_of, net::Ipv4Addr};

use itertools::Itertools;
use log::{debug, error};

use crate::vrrp::constants::{
    BROADCAST_MAC, ETH_PROTO_ARP, ETH_PROTO_IP, HW_TYPE_ETH, IPPROTO_VRRPV2, IP_DSCP, IP_VER_IHL,
    NLATTR_ALIGNTO, NLMSG_ALIGNTO, SOCKET_TTL, VRRP_HDR_LEN, VRRP_MCAST_ADDR, VRRP_VER_TYPE,
};

// Size 8
/* used for adding / deleting ip address to network interface via Netlink socket */
pub struct IfAddrMessage {
    pub ifa_family: u8,
    ifa_prefixlen: u8,
    ifa_flags: u8,
    ifa_scope: u8,
    pub ifa_index: u32,
}

impl IfAddrMessage {
    pub fn _print(&self) {
        debug!("\tifa_family {}", self.ifa_family);
        debug!("\tifa_prefixlen {}", self.ifa_prefixlen);
        debug!("\tifa_flags {}", self.ifa_flags);
        debug!("\tifa_scope {}", self.ifa_scope);
        debug!("\tifa_index {}", self.ifa_index);
    }

    pub fn new(family: u8, prefix_len: u8, flags: u8, scope: u8, index: u32) -> IfAddrMessage {
        IfAddrMessage {
            ifa_family: family,
            ifa_prefixlen: prefix_len,
            ifa_flags: flags,
            ifa_scope: scope,
            ifa_index: index,
        }
    }

    pub fn from_slice(buf: &[u8]) -> Option<IfAddrMessage> {
        if buf.len() < size_of::<IfAddrMessage>() {
            None
        } else {
            Some(IfAddrMessage {
                ifa_family: buf[0],
                ifa_prefixlen: buf[1],
                ifa_flags: buf[2],
                ifa_scope: buf[3],
                ifa_index: u32::from_ne_bytes(buf[4..8].try_into().unwrap()),
            })
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
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
pub struct NetLinkMessageHeader {
    pub msg_len: u32,
    pub msg_type: u16,
    msg_flags: u16,
    msg_seq: u32,
    msg_pid: u32,
}

impl NetLinkMessageHeader {
    pub fn print(&self) {
        debug!("\tnlmsg_len {}", self.msg_len);
        debug!("\tnlmsg_type {}", self.msg_type);
        debug!("\tnlmsg_flags {}", self.msg_flags);
        debug!("\tnlmsg_seq {}", self.msg_seq);
        debug!("\tnlmsg_pid {}", self.msg_pid);
    }

    pub fn from_slice(buf: &[u8]) -> Option<NetLinkMessageHeader> {
        if buf.len() < size_of::<NetLinkMessageHeader>() {
            None
        } else {
            Some(NetLinkMessageHeader {
                msg_len: u32::from_ne_bytes(buf[0..4].try_into().unwrap()),
                msg_type: u16::from_ne_bytes(buf[4..6].try_into().unwrap()),
                msg_flags: u16::from_ne_bytes(buf[6..8].try_into().unwrap()),
                msg_seq: u32::from_ne_bytes(buf[8..12].try_into().unwrap()),
                msg_pid: u32::from_ne_bytes(buf[12..16].try_into().unwrap()),
            })
        }
    }

    pub fn new(
        msg_len: u32,
        msg_type: u16,
        msg_flags: u16,
        msg_seq: u32,
        msg_pid: u32,
    ) -> NetLinkMessageHeader {
        NetLinkMessageHeader {
            msg_len,
            msg_type,
            msg_flags,
            msg_seq,
            msg_pid,
        }
    }

    pub fn to_bytes(&mut self, payload: &mut Vec<u8>) -> Vec<u8> {
        let data_len = (size_of::<NetLinkMessageHeader>() + payload.len()) as u32;
        // Pad to multiple of NLMSG_ALIGNTO
        let pad_len = ((data_len + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1)) - data_len;

        self.msg_len = data_len + pad_len;

        let mut bytes: Vec<u8> = Vec::new();

        bytes.extend_from_slice(&self.msg_len.to_ne_bytes());
        bytes.extend_from_slice(&self.msg_type.to_ne_bytes());
        bytes.extend_from_slice(&self.msg_flags.to_ne_bytes());
        bytes.extend_from_slice(&self.msg_seq.to_ne_bytes());
        bytes.extend_from_slice(&self.msg_pid.to_ne_bytes());

        for _ in 0..pad_len {
            bytes.push(0u8);
        }

        bytes.append(payload);

        bytes
    }
}

pub struct NetLinkAttribute {
    pub header: NetLinkAttributeHeader,
    pub payload: Vec<u8>,
}

impl NetLinkAttribute {
    pub fn print(&self) {
        debug!("\tnla_len: {}", self.header.nla_len);
        debug!("\tnla_type: {}", self.header.nla_type);
        debug!("\tpayload: {}", self.payload.iter().map(|byte| format!("{:02x?}", byte)).join(" "));
    }

    pub fn new(header: NetLinkAttributeHeader) -> NetLinkAttribute {
        NetLinkAttribute {
            header,
            payload: Vec::<u8>::new(),
        }
    }
}

// TOOD: refactor to util
pub fn pad_len(len: usize, align_to: usize) -> usize {
    (len + align_to - 1) & !(align_to - 1)
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
pub struct NetLinkAttributeHeader {
    pub nla_len: u16,
    pub nla_type: u16,
}

impl NetLinkAttributeHeader {
    pub fn new(nla_len: u16, nla_type: u16) -> NetLinkAttributeHeader {
        NetLinkAttributeHeader { nla_len, nla_type }
    }

    pub fn from_slice(buf: &[u8]) -> Option<NetLinkAttributeHeader> {
        if buf.len() < size_of::<NetLinkAttributeHeader>() {
            None
        } else {
            Some(NetLinkAttributeHeader {
                nla_len: u16::from_ne_bytes(buf[0..2].try_into().unwrap()),
                nla_type: u16::from_ne_bytes(buf[2..4].try_into().unwrap()),
            })
        }
    }

    pub fn to_bytes(&self, payload: &mut Vec<u8>) -> Vec<u8> {
        let pad_len = ((self.nla_len + NLATTR_ALIGNTO - 1) & !(NLATTR_ALIGNTO - 1))
            - payload.len() as u16
            - size_of::<NetLinkAttributeHeader>() as u16;
        let mut byte_vec = Vec::<u8>::new();

        byte_vec.extend_from_slice(&self.nla_len.to_ne_bytes());
        byte_vec.extend_from_slice(&self.nla_type.to_ne_bytes());
        byte_vec.append(payload);

        for _ in 0..pad_len {
            byte_vec.push(0u8);
        }
        byte_vec
    }
}

// RFC 826
pub struct GarpPacket {
    mac_dst: [u8; 6],
    mac_src: [u8; 6],
    eth_proto: u16,

    hw_type: u16,
    proto_type: u16,
    hw_len: u8,    /* 6 for MAC */
    proto_len: u8, /* 4 for IPv4 */
    op_code: u16,
    hw_addr_src: [u8; 6],
    proto_addr_src: [u8; 4],
    hw_addr_dst: [u8; 6],
    proto_addr_dst: [u8; 4],
}

impl GarpPacket {
    pub fn new(virtual_ip: Ipv4Addr, local_hw_addr: [u8; 6]) -> GarpPacket {
        GarpPacket {
            mac_dst: BROADCAST_MAC,
            // mac_src: VIRTUAL_ROUTER_MAC,
            mac_src: local_hw_addr,
            eth_proto: ETH_PROTO_ARP,
            hw_type: HW_TYPE_ETH,
            proto_type: ETH_PROTO_IP as u16,
            hw_len: 6,
            proto_len: 4,
            op_code: 1,
            // hw_addr_src: VIRTUAL_ROUTER_MAC,
            hw_addr_src: local_hw_addr,
            proto_addr_src: virtual_ip.octets(),
            hw_addr_dst: BROADCAST_MAC,
            proto_addr_dst: virtual_ip.octets(),
        }
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

#[derive(Debug, Clone)]
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

    pub vip_addresses: Vec<Ipv4Addr>,
    pub auth_data: Vec<u8>,
}

impl VrrpV2Packet {
    pub fn build(
        router_id: u8,
        priority: u8,
        auth_type: u8,
        advert_int: u8,
        src_addr: Ipv4Addr,
        vip_addresses: Vec<Ipv4Addr>,
        auth_data: Vec<u8>,
    ) -> VrrpV2Packet {
        VrrpV2Packet {
            _ip_ver: IP_VER_IHL,
            _ip_dscp: IP_DSCP,
            _ip_length: 0,
            _ip_id: 0,
            _ip_flags: 0,
            ip_ttl: SOCKET_TTL,
            _ip_proto: IPPROTO_VRRPV2 as u8,
            _ip_checksum: 0,
            ip_src: src_addr.octets(),
            ip_dst: VRRP_MCAST_ADDR.octets(),
            ver_type: VRRP_VER_TYPE,
            router_id,
            priority,
            cnt_ip_addr: vip_addresses.len() as u8,
            auth_type,
            advert_int,
            checksum: 0,
            vip_addresses,
            auth_data,
        }
    }

    pub fn from_slice(buf: &[u8]) -> Option<VrrpV2Packet> {
        if buf.len() < VRRP_HDR_LEN {
            None
        } else {
            let cnt_ip_addr = buf[23];
            if buf.len() < VRRP_HDR_LEN + (4 * cnt_ip_addr as usize) {
                None
            } else {
                let mut pkt = VrrpV2Packet {
                    _ip_ver: buf[0],
                    _ip_dscp: buf[1],
                    _ip_length: u16::from_be_bytes(buf[2..4].try_into().unwrap()),
                    _ip_id: u16::from_be_bytes(buf[4..6].try_into().unwrap()),
                    _ip_flags: u16::from_be_bytes(buf[6..8].try_into().unwrap()),
                    ip_ttl: buf[8],
                    _ip_proto: buf[9],
                    _ip_checksum: u16::from_be_bytes(buf[10..12].try_into().unwrap()),
                    ip_src: buf[12..16].try_into().unwrap(),
                    ip_dst: buf[16..20].try_into().unwrap(),
                    ver_type: buf[20],
                    router_id: buf[21],
                    priority: buf[22],
                    cnt_ip_addr,
                    auth_type: buf[24],
                    advert_int: buf[25],
                    checksum: u16::from_be_bytes(buf[26..28].try_into().unwrap()),
                    vip_addresses: Vec::new(),
                    auth_data: Vec::new(),
                };

                for ind in 0..cnt_ip_addr {
                    pkt.vip_addresses.push(Ipv4Addr::from(u32::from_be_bytes(
                        buf[VRRP_HDR_LEN + (ind * 4) as usize
                            ..VRRP_HDR_LEN + 4 + (ind * 4) as usize]
                            .try_into()
                            .unwrap(),
                    )));
                }

                for ind in VRRP_HDR_LEN + (4 * cnt_ip_addr as usize)..buf.len() {
                    pkt.auth_data.push(buf[ind]);
                }

                Some(pkt)
            }
        }
    }

    pub fn print(&self) {
        debug!("\tVRRP Ver:  {}", self.ver_type >> 4);
        debug!("\tVRRP Type: {}", self.ver_type & 0xF);
        debug!("\tSource:    {}", Ipv4Addr::from(self.ip_src));
        debug!("\tRouterId:  {}", self.router_id);
        debug!("\tPriority:  {}", self.priority);
        debug!("\tAuthType:  {}", self.auth_type);
        debug!("\tInterval:  {}", self.advert_int);
        debug!("\tVIP count: {}", self.cnt_ip_addr);
        for ind in 0..self.vip_addresses.len() {
            debug!("\t\t{}", self.vip_addresses[ind].to_string());
        }
        debug!(
            "\tAuthData:  {}",
            String::from_utf8_lossy(self.auth_data.as_slice())
        );
    }

    pub fn to_bytes(&mut self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();
        match self.calculate_checksum() {
            Ok(_) => {}
            Err(err) => {
                error!(
                    "Error while calculating packet checksum: {}",
                    err.to_string()
                );
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

    /* RFC 3768 7.1 Receiving VRRP Packets */
    pub fn verify(&self) -> Result<(), String> {
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
