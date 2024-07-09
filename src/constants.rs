use std::net::Ipv4Addr;

pub const AF_INET: i32 = 0x02;
pub const AF_PACKET: i32 = 0x11;

pub const SOCK_RAW: i32 = 0x03;

pub const IPPROTO_ICMP: i32 = 0x01;
pub const IPPROTO_ICMPV6: i32 = 0x3A;
pub const IPPROTO_TCP: i32 = 6;
pub const IPPROTO_UDP: i32 = 0x11;
pub const IPPROTO_IP: i32 = 0x00;
pub const IPPROTO_IPV6: i32 = 0x29;
pub const IPPROTO_VRRPV2: i32 = 0x70;
// ARP 2054
pub const ETH_PROTO_ARP: i32 = 0x0806;
pub const ETH_PROTO_IP: i32 = 0x0800;

pub const IFR_FLAG_UP: i16 = 0x01;
pub const IFR_FLAG_RUNNING: i16 = 0x40;
pub const IFR_FLAG_MULTICAST: i16 = 0x1000;

pub const SOCKET_TTL: u8 = 0xFF;

pub const VRRP_MCAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 18);

pub const VIRTUAL_ROUTER_MAC: [u8; 6] = [0, 0, 94, 0, 1, 0];

pub const HW_TYPE_ETH: u16 = 0x01;
