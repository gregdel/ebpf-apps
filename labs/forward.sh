#!/bin/sh
set -e

_clean_link() {
	ip link show "$1" >/dev/null 2>/dev/null || return 0
	ip link del "$1"
}
_clean_link "lab-br"
_clean_link "lab-a"
_clean_link "lab-b"
_clean_link "lab-fwd"

_clean_ns() {
	ip netns del "$1" >/dev/null 2>/dev/null || return 0
}
_clean_ns "lab-a"
_clean_ns "lab-b"
_clean_ns "lab-fwd"

sleep 1

# Create the interfaces
ip link add "lab-br" type bridge
ip link add "lab-a" type veth peer name "lab-a-br"
ip link add "lab-b" type veth peer name "lab-b-br"
ip link add "lab-fwd" type veth peer name "lab-fwd-br"

# Add them to the bridge
ip link set "lab-br" up
ip link set "lab-a-br" master "lab-br" up
ip link set "lab-b-br" master "lab-br" up
ip link set "lab-fwd-br" master "lab-br" up

# Create a forwarding namespace
ip netns add "lab-fwd"
ip netns add "lab-a"
ip netns add "lab-b"
ip link set "lab-a" netns "lab-a" address 02:00:00:00:00:0a up
ip link set "lab-b" netns "lab-b" address 02:00:00:00:00:0b up
ip link set "lab-fwd" netns "lab-fwd" address 02:00:00:00:00:ff up

# Add the IPs
ip -n "lab-a" addr add "100.64.0.1/32" dev "lab-a"
ip -n "lab-b" addr add "100.64.0.2/32" dev "lab-b"
ip -n "lab-fwd" addr add "100.64.0.254/32" dev "lab-fwd"

# Add the routes
ip -n "lab-a" route add "100.64.0.254" dev "lab-a"
ip -n "lab-a" route add "100.64.0.0/24" via "100.64.0.254"
ip -n "lab-b" route add "100.64.0.254" dev "lab-b"
ip -n "lab-b" route add "100.64.0.0/24" via "100.64.0.254"
ip -n "lab-fwd" route add "100.64.0.1/32" dev "lab-fwd"
ip -n "lab-fwd" route add "100.64.0.2/32" dev "lab-fwd"

# Disable ICMP redirects in the forwarder
ip netns exec "lab-fwd" sysctl -w "net.ipv4.conf.lab-fwd.send_redirects=0"
