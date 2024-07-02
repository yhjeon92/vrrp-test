## VRRP Testing Tool

- Test suite for VRRPv2 packet receiving / transmission, written in Rust programming language.

#### Build

```shell
$ cargo build
```

#### Run

```shell
# Run in read-only mode (Receives VRRPv2 packet on the given interface and print it)
$ sudo vrrp-test -i $TARGET_INTERFACE

# Run in router mode (Send VRRPv2 advertisement packet periodically)
$ sudo vrrp-test -i $TARGET_INTERFACE -r
```
