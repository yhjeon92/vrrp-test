use std::net::Ipv4Addr;

// Socket
pub const _AF_UNSPEC: u8 = 0x00;
pub const AF_INET: u8 = 0x02;
pub const AF_INET6: u8 = 0x0A;
pub const _AF_NETLINK: u8 = 0x10;
pub const AF_PACKET: u8 = 0x11;

pub const SOCK_DGRAM: i32 = 0x02;
pub const SOCK_RAW: i32 = 0x03;

// Socket Flags
pub const SOCK_NONBLOCK: i32 = 0x800;
pub const SOCK_CLOEXEC: i32 = 0x80000;

pub const _IPPROTO_ICMP: i32 = 0x01;
pub const _IPPROTO_ICMPV6: i32 = 0x3A;
pub const _IPPROTO_TCP: i32 = 6;
pub const _IPPROTO_UDP: i32 = 0x11;
pub const IPPROTO_IP: i32 = 0x00;
pub const _IPPROTO_IPV6: i32 = 0x29;
pub const IPPROTO_VRRPV2: i32 = 0x70;
// ARP 2054
pub const ETH_PROTO_ARP: u16 = 0x0806;
pub const ETH_PROTO_IP: u16 = 0x0800;

pub const IFR_FLAG_UP: i16 = 0x01;
pub const IFR_FLAG_RUNNING: i16 = 0x40;
pub const IFR_FLAG_MULTICAST: i16 = 0x1000;

// NetLink Message
pub const NLMSG_ALIGNTO: u32 = 4;

// NetLink Address Group
pub const RTMGRP_LINK: u32 = 1;
pub const RTMGRP_IPV4_IFADDR: u32 = 0x10;
pub const _RTMGRP_IPV6_IFADDR: u32 = 0x100;

// Message Types (rtnetlink)
pub const RTM_NEWADDR: u16 = 0x14;
pub const RTM_DELADDR: u16 = 0x15;
pub const _RTM_GETADDR: u16 = 0x16;
// Message Types (netlink)
pub const _NLMSG_ERROR: u16 = 0x02;

// NetLink Message Flags
pub const NLM_F_REQUEST: u16 = 0x01;
pub const _NLM_F_MULTI: u16 = 0x02;
pub const NLM_F_ACK: u16 = 0x04;
pub const NLM_F_EXCL: u16 = 0x200;
pub const NLM_F_CREATE: u16 = 0x400;

pub const _NLM_F_ROOT: u16 = 0x100;
pub const _NLM_F_MATCH: u16 = 0x200;
pub const _NLM_F_ATOMIC: u16 = 0x400;
pub const _NLM_F_DUMP: u16 = _NLM_F_ROOT | _NLM_F_MATCH;

// IFA SCOPE
pub const RT_SCOPE_UNIVERSE: u8 = 0;

// NetLink attributes
pub const NLATTR_ALIGNTO: u16 = 4;

// NetLink attribute Types
pub const IFA_ADDRESS: u16 = 0x01;
pub const IFA_LOCAL: u16 = 0x02;
pub const _IFA_LABEL: u16 = 0x03;
pub const _IFA_BROADCAST: u16 = 0x04;
pub const _IFA_CACHEINFO: u16 = 0x06;
pub const _IFA_FLAGS: u16 = 0x08;

pub const SOCKET_TTL: u8 = 0xFF;

// IP Packet
pub const IP_VER_IHL: u8 = 0x45; /* Version 4 - IHL 5 (no option) */
pub const IP_DSCP: u8 = 0xC0;

// VRRPV2

pub const VRRP_VER_TYPE: u8 = 0x21; /* Version 2 - Type 1 */
pub const VRRP_HDR_LEN: usize = 28;
pub const VRRP_MCAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 18);

pub const BROADCAST_MAC: [u8; 6] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
pub const BROADCAST_MAC_SOCKADDR_LL: [u8; 8] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0];
pub const _VIRTUAL_ROUTER_MAC: [u8; 6] = [0, 0, 94, 0, 1, 0];

pub const HW_TYPE_ETH: u16 = 0x01;
