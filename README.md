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

```toml
interface = "eth0"
router_id = 50
priority = 100
advert_int = 5
vip_addresses = [ "192.168.35.200/24" ]
```

- `interface` is the name of network interface to run virutal router on.
- `router_id` is the virtual router Id.
- `priority` is the priority assigned to virtual router.
- `advert_int` is the interval to multicast VRRPv2 advertisement. Unit is second.
- `vip_addresses` is the TOML array of IPv4 address (with netmask length) of virtual IPs you'd like to assign to the virtual router.

#### Running with Docker compose

- Build Docker image

```shell
$ docker build -t vrrp-test:0.1 .
```

- Run Docker compose service

```shell
$ docker compose up -d
```
