#!/bin/bash

if [[ -z "${VRRP_IF}" ]]; then
  export VRRP_IF="eth0"
fi

if [[ -z "${VRRP_RID}" ]]; then
  export VRRP_RID=50
fi

if [[ -z "${VRRP_PRIORITY}" ]]; then
  export VRRP_PRIORITY=100
fi

if [[ -z "${VRRP_VIP}" ]]; then
  export VRRP_VIP="172.18.0.100"
fi

if [[ -z "${VRRP_ADVERT_INT}" ]]; then
  export VRRP_ADVERT_INT=3
fi

if [[ -z "${VRRP_NETMASK_LEN}" ]]; then
  export VRRP_NETMASK_LEN=16
fi

if [ ! -f ./vrrp.toml ]; then
  printf "interface = \"$VRRP_IF\"\nrouter_id = $VRRP_RID\npriority = $VRRP_PRIORITY\nadvert_int = $VRRP_ADVERT_INT\nvip_addresses = [ \"$VRRP_VIP/$VRRP_NETMASK_LEN\" ]" >> ./vrrp.toml
fi

if [[ -z "${VERBOSE}" ]]; then
  vrrp-test -i eth0 -r -c vrrp.toml
else
  vrrp-test -i eth0 -r -v -c vrrp.toml
fi
