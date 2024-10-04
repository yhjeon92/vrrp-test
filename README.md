## VRRP Testing Tool

- Test suite for virtual router running with VRRPv2 protocol, written in Rust programming language. Only available on Linux based operating system.

#### Build

```shell
$ cargo build

$ cargo build --release
```

- Executable binary will be created under `target/debug` and `target/release`, respectively.

#### Run

- The compiled binary requires two Linux system capabilities to function - `CAP_NET_RAW` and `CAP_NET_ADMIN`. You can simply run it with `sudo` command, or manually set the capabilities using `setcap` system command.

```shell
$ setcap cap_net_admin,cap_net_raw=+ep target/debug/vrrp-test
$ setcap cap_net_admin,cap_net_raw=+ep target/release/vrrp-test
```

- Below example runs a read-only application, which listens to the given network interface and prints received VRRPv2 advert packet.

```shell
$ vrrp-test -i $NETWORK_INTERFACE
```

- Below example runs a virtual router, which participates in cluster on the network interface and tries to occupy virtual ip if no master node exists. Application refers to `vrrp.toml` in working directory as configuration file by default.

```shell
$ vrrp-test -r
```

- Configuration file path can be customized with command line argument option `-c`.

```shell
$ vrrp-test -r -c $CONFIG_FILE_PATH
```

#### Configuration

- Copy the sample `vrrp.toml.sample` in repository, adjust the items to suit your need. Default configuration path is set to `vrrp.toml` in working directory.

| Parameter Name | Type | Optional | Description |
| --- | --- | --- | --- |
| interface | String |  | Name of network interface to run virtual router on. |
| router_id | Integer |  | Virtual router Id. The value is used to distinguish Virtual Router clusters in a network. |
| priority | Integer |  | Priority assigned to this virtual router instance. |
| advert_int | Integer |  | Interval to multicast VRRP advertisement. Unit is in second. |
| vip_addresses | String Array |  | TOML Array of IPv4 address with netmask length of virtual IPv4 addresses you'd like to assign to this virtual router instance. |
| pre_promote_script | String | Optional | OS command to execute prior to BACKUP -> MASTER promotion. |
| pre_demote_script | String | Optional | OS command to execute prior to MASTER -> BACKUP demotion. |
| unicast_peers | String Array | Optional | List of peer router's IPv4 addresses. Once given the packet will be unicasted instead of being mutlicasted. |

##### Example

```toml
interface = "eth0"
router_id = 50
priority = 100
advert_int = 5
vip_addresses = [ "192.168.35.200/24" ]
pre_promote_script = "sh -C /path/to/custom_script.sh"
pre_demote_script = "/usr/bin/echo >> test.log"
unicast_peers = [ "192.168.35.3", "192.168.35.4" ]
```

#### Running with Docker compose

```shell
$ docker compose up -d
```
