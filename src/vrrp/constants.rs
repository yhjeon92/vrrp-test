use std::net::Ipv4Addr;

// Socket
// <linux/x86_64-linux-gnu/bits/socket.h>
pub const _AF_UNSPEC: i32 = 0x00;
pub const AF_INET: i32 = 0x02;
pub const _AF_NETLINK: u16 = 0x10;
pub const AF_PACKET: i32 = 0x11;

pub const SOCK_DGRAM: i32 = 0x02;
pub const SOCK_RAW: i32 = 0x03;

// Socket Flags
pub const SOCK_CLOEXEC: i32 = 0x80000;

// Protocol
// <linux/in.h>
pub const _IPPROTO_ICMP: i32 = 0x01;
pub const _IPPROTO_ICMPV6: i32 = 0x3A;
pub const IPPROTO_TCP: i32 = 6;
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
// Message Types <linux/netlink.h>
pub const NLMSG_ERROR: u16 = 0x02;
pub const _NLMSG_DONE: u16 = 0x03;

pub const NLMSG_ALIGNTO: u32 = 4; // padding length

pub const NLMSG_HDR_SIZE: usize = 16;
pub const GENLMSG_HDR_SIZE: usize = 4;

// Message Types (rtnetlink)
pub const RTM_NEWADDR: u16 = 0x14;
pub const RTM_DELADDR: u16 = 0x15;
pub const _RTM_GETADDR: u16 = 0x16;

// Message Types (netlink)
pub const _NLMSG_ERROR: u16 = 0x02;

// <linux/genetlink.h>
// Message Types (generic netlink)
pub const GENL_ID_CTRL: u16 = 0x10;

pub const CTRL_CMD_GETFAMILY: u8 = 0x03;
pub const _CTRL_CMD_GETOPS: u8 = 0x06;

// Generic NetLink Attribute Types
pub const _CTRL_ATTR_UNSPEC: u16 = 0x00;
pub const CTRL_ATTR_FAMILY_ID: u16 = 0x01;
pub const CTRL_ATTR_FAMILY_NAME: u16 = 0x02;
pub const _CTRL_ATTR_VERSION: u16 = 0x03;
pub const _CTRL_ATTR_HDRSIZE: u16 = 0x04;
pub const _CTRL_ATTR_MAXATTR: u16 = 0x05;
pub const _CTRL_ATTR_OPS: u16 = 0x06;
pub const _CTRL_ATTR_MCAST_GROUPS: u16 = 0x07;

// Command Attributes (generic netlink)
// <linux/ip_vs.h>
pub const IPVS_CMD_NEW_SERVICE: u8 = 0x01;
pub const IPVS_CMD_GET_SERVICE: u8 = 0x04;
pub const IPVS_CMD_NEW_DEST: u8 = 0x05;
pub const _IPVS_CMD_GET_INFO: u8 = 0x0F;

// IPVS nl attribute type in response to command
pub const IPVS_CMD_ATTR_SERVICE: u16 = 0x01;
pub const _IPVS_CMD_ATTR_DEST: u16 = 0x02;

// NetLink Message Flags
pub const NLM_F_REQUEST: u16 = 0x01;
pub const _NLM_F_MULTI: u16 = 0x02;
pub const NLM_F_ACK: u16 = 0x04;

// Modifiers to GET request
pub const NLM_F_ROOT: u16 = 0x100;
pub const NLM_F_MATCH: u16 = 0x200;
pub const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;
pub const _NLM_F_ATOMIC: u16 = 0x400;

// Modifiers to NEW request
pub const _NLM_F_REPLACE: u16 = 0x100;
pub const NLM_F_EXCL: u16 = 0x200;
pub const NLM_F_CREATE: u16 = 0x400;

// IFA SCOPE
pub const RT_SCOPE_UNIVERSE: u8 = 0;

// NetLink attributes
pub const NLATTR_ALIGNTO: u16 = 4;

pub const IFA_ADDRESS: u16 = 1;
pub const IFA_LOCAL: u16 = 2;
pub const _IFA_LABEL: u16 = 3;

// NetLink IPVS attributes
// Service Attributes
pub const IPVS_SVC_ATTR_AF: u16 = 1;
pub const IPVS_SVC_ATTR_PROTOCOL: u16 = 2;
pub const IPVS_SVC_ATTR_ADDR: u16 = 3;
pub const IPVS_SVC_ATTR_PORT: u16 = 4;
pub const _IPVS_SVC_ATTR_FWMARK: u16 = 5;

pub const IPVS_SVC_ATTR_SCHED_NAME: u16 = 6;
pub const IPVS_SVC_ATTR_FLAGS: u16 = 7;
pub const IPVS_SVC_ATTR_TIMEOUT: u16 = 8;
pub const IPVS_SVC_ATTR_NETMASK: u16 = 9;

// Destination Attributes
pub const IPVS_DEST_ATTR_ADDR: u16 = 1;
pub const IPVS_DEST_ATTR_PORT: u16 = 2;
pub const IPVS_DEST_ATTR_FWD_METHOD: u16 = 3;
pub const IPVS_DEST_ATTR_WEIGHT: u16 = 4;
pub const IPVS_DEST_ATTR_U_THRESH: u16 = 5;
pub const IPVS_DEST_ATTR_L_THRESH: u16 = 6;
pub const IPVS_DEST_ATTR_ADDR_FAMILY: u16 = 11;

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
