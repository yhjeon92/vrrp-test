## VRRP Testing Tool

- Test suite for virtual router running with VRRPv2 protocol, written in Rust programming language. Only available on Linux based operating system.

#### Build

```shell
$ cargo build

$ cargo build --release
```

- Executable binary will be created under `target/debug` and `target/release`, respectively.

#### Run

```shell
# Run in read-only mode (Receives VRRPv2 packet on the given interface and print it)
$ sudo vrrp-test -i $TARGET_INTERFACE

# Run in router mode (Send VRRPv2 advertisement packet periodically)
$ sudo vrrp-test -r
```

- Specify configuration file path with command line option -c

```shell
$ sudo vrrp-test -r -c $CONFIG_FILE_PATH
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

#### Testing with Docker compose

- Build Docker image

```shell
$ docker build -t vrrp-test:0.1 .
```

- Run Docker compose service

```shell
$ docker compose up -d
```
