#!/bin/sh
# /provisioning/alpine-init.sh

HOSTNAME=$1
echo "Starting Day-0 initialization for $HOSTNAME..."

hostname $HOSTNAME
echo $HOSTNAME > /etc/hostname

apk add --no-cache yq iproute2 openssh
ssh-keygen -A
echo "root:root_password" | chpasswd

# Explicitly allow root login for the Netmiko SSH connection
sed -i 's/^#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
/usr/sbin/sshd

VLAN_ID=$(yq eval ".$HOSTNAME.vlan_id" /tmp/init.yml)
IP=$(yq eval ".$HOSTNAME.ip" /tmp/init.yml)
GW=$(yq eval ".$HOSTNAME.gw" /tmp/init.yml)
VLAN_IFACE="eth1.${VLAN_ID}"

# eth1 itself stays up but untagged/IP-less - all traffic for this host is
# carried on the 802.1Q sub-interface below, matching the
# "vlan encap single-tagged vlan-id <id>" sub-interface configured on the
# SR Linux distribution switch port at the other end of this link.
ip link set eth1 up
ip link add link eth1 name "$VLAN_IFACE" type vlan id "$VLAN_ID"
ip link set "$VLAN_IFACE" up

ip addr add $IP dev "$VLAN_IFACE"
ip route add default via $GW dev "$VLAN_IFACE"

echo "export PS1='\u@\h:\w# '" >> /root/.profile
echo "Initialization complete. Hostname: $HOSTNAME | VLAN: $VLAN_ID | IP: $IP | GW: $GW"