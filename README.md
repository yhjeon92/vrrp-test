## VRRP Testing Tool

- Test suite for VRRPv2 packet receiving / transmission, written in Rust programming language.

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

- vrrp.toml
