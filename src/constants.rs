use std::net::Ipv4Addr;

pub const AF_INET: i32 = 0x02;
pub const _AF_NETLINK: u16 = 0x10;
pub const AF_PACKET: i32 = 0x11;

pub const SOCK_RAW: i32 = 0x03;

pub const _IPPROTO_ICMP: i32 = 0x01;
pub const _IPPROTO_ICMPV6: i32 = 0x3A;
pub const _IPPROTO_TCP: i32 = 6;
pub const _IPPROTO_UDP: i32 = 0x11;
pub const _IPPROTO_IP: i32 = 0x00;
pub const _IPPROTO_IPV6: i32 = 0x29;
pub const IPPROTO_VRRPV2: i32 = 0x70;
// ARP 2054
pub const ETH_PROTO_ARP: i32 = 0x0806;
pub const ETH_PROTO_IP: i32 = 0x0800;

pub const IFR_FLAG_UP: i16 = 0x01;
pub const IFR_FLAG_RUNNING: i16 = 0x40;
pub const IFR_FLAG_MULTICAST: i16 = 0x1000;

// NetLink Message
pub const NLMSG_ALIGNTO: u32 = 4;

// Message Types (rtnetlink)
pub const RTM_NEWADDR: u16 = 0x14;
// Message Types (netlink)
pub const _NLMSG_ERROR: u16 = 0x02;

// NetLink Message Flags
pub const NLM_F_REQUEST: u16 = 0x01;
pub const _NLM_F_MULTI: u16 = 0x02;
pub const NLM_F_ACK: u16 = 0x04;
pub const NLM_F_EXCL: u16 = 0x200;
pub const NLM_F_CREATE: u16 = 0x400;

// IFA SCOPE
pub const RT_SCOPE_UNIVERSE: u8 = 0;

// NetLink attributes
pub const NLATTR_ALIGNTO: u16 = 4;

pub const IFA_ADDRESS: u16 = 1;
pub const IFA_LOCAL: u16 = 2;
pub const IFA_LABEL: u16 = 3;

pub const SOCKET_TTL: u8 = 0xFF;

pub const VRRP_MCAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 18);

pub const VIRTUAL_ROUTER_MAC: [u8; 6] = [0, 0, 94, 0, 1, 0];

pub const HW_TYPE_ETH: u16 = 0x01;
