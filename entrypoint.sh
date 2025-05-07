#!/bin/bash

export VRRP_IF="${VRRP_IF:-eth0}"
export VRRP_RID="${VRRP_RID:-50}"
export VRRP_PRIORITY="${VRRP_PRIORITY:-100}"
export VRRP_VIP="${VRRP_VIP:-172.18.0.100}"
export VRRP_ADVERT_INT="${VRRP_ADVERT_INT:-3}"
export VRRP_NETMASK_LEN="${VRRP_NETMASK_LEN:-16}"

if [ ! -f ./vrrp.toml ]; then
  printf "interface = \"$VRRP_IF\"\nrouter_id = $VRRP_RID\npriority = $VRRP_PRIORITY\nadvert_int = $VRRP_ADVERT_INT\nvip_addresses = [ \"$VRRP_VIP/$VRRP_NETMASK_LEN\" ]" >> ./vrrp.toml
fi

if [[ -z "${VERBOSE}" ]]; then
  exec vrrp-test -i eth0 -r -c vrrp.toml
else
  exec vrrp-test -i eth0 -r -v -c vrrp.toml
fi
