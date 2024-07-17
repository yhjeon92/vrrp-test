## VRRP Testing Tool

- Test suite for VRRPv2 packet receiving / transmission, written in Rust programming language. Only available on Linux based operating system.

#### Build

```shell
$ cargo build

$ cargo build --release
```

#### Run

```shell
# Run in read-only mode (Receives VRRPv2 packet on the given interface and print it)
$ sudo vrrp-test -i $TARGET_INTERFACE

# Run in router mode (Send VRRPv2 advertisement packet periodically)
$ sudo vrrp-test -i $TARGET_INTERFACE -r
```

- Specify configuration file path with command line option -c

```shell
$ sudo vrrp-test -i $TARGET_INTERFACE -c $CONFIG_FILE_PATH
```

#### Configuration

- Copy the sample `vrrp.toml.sample` in repository, adjust the items to suit your need. Default configuration path is set to `vrrp.toml` in working directory.

```toml
interface = "eth0"
router_id = 50
priority = 100
advert_int = 5
virtual_ip = "192.168.35.200"
netmask_len = 24
```

- `interface` is the name of network interface to run virutal router on.
- `router_id` is the virtual router Id.
- `priority` is the priority assigned to virtual router.
- `advert_int` is the interval to multicast VRRPv2 advertisement. Unit is second.
- `virtual_ip` is the IPv4 address of virtual IP.
- `netmask_len` is the subnet mask length of above given virtual ip.

#### Testing with Docker compose

- Build Docker image

```shell
$ docker build -t vrrp-test:0.1 .
```

- Run Docker compose service

```shell
$ docker compose up -d
```
