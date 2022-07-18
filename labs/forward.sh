#!/bin/sh
set -e

_mute() {
	"$@" >/dev/null 2>/dev/null
}

_start() {
	echo "Starting"

	_setup_routing
	_setup_client "a" "100.64.0.1" "02:00:00:00:00:0a" "100.64.0.254"
	_setup_client "b" "100.64.0.2" "02:00:00:00:00:0b" "100.64.0.254"
	_setup_client "xdp" "100.64.0.254/24" "02:00:00:00:00:ff"
	_setup_bridge
}

_stop() {
	echo "Stopping"
	_mute ip netns del lab     ||:
	_mute ip netns del lab-a   ||:
	_mute ip netns del lab-b   ||:
	_mute ip netns del lab-xdp ||:
}

_xdp() {
	ip -n lab link set lab-xdp xdp off
	ip -n lab link set lab-xdp \
		xdp object ../.output/forward-xdp.bpf.o section xdp_dummy
	ip netns exec lab-xdp ../forward-xdp
}

_usage() {
	echo "$(basename "$0"):"
	echo "  start - start the lab"
	echo "  xdp   - start the xdp program"
	echo "  stop  - stop the lab"
	echo "  run   - stop + start + xdp"
	exit 0
}

_run() {
	_stop
	_start
	_xdp
}

_setup_routing() {
	ip netns add lab
	ip -n lab link set lo up
}

_sysctl() {
	ns=$1
	key=$2
	value=$3
	ip netns exec "$ns" sysctl -qw "$key=$value"
}

_setup_bridge() {
	ip -n lab link add br0 type bridge
	ip -n lab link set br0 up
	ip -n lab link set lab-a master br0
	ip -n lab link set lab-b master br0
	ip -n lab link set lab-xdp master br0

	# Disable ICMP redirects
	_sysctl "lab-xdp" "net.ipv4.conf.all.send_redirects" "0"
	_sysctl "lab-xdp" "net.ipv4.conf.out.send_redirects" "0"
}

_setup_client() {
	ns="lab-$1"
	ip=$2
	lladdr=$3
	gw=$4
	ip netns add "$ns"
	_sysctl "$ns" "net.ipv6.conf.all.disable_ipv6" "1"
	_sysctl "$ns" "net.ipv6.conf.default.disable_ipv6" "1"
	ip -n "$ns" link add out type veth peer name "$ns" netns "lab"
	ip -n "$ns" addr add "$ip" dev out
	ip -n "$ns" link set out address "$lladdr" up
	ip -n "$ns" link set lo up
	ip -n lab link set "$ns" up
	ip -n lab route add "${ip%%/*}" dev "$ns" scope link
	# Don't delay the checksum calculation
	_mute ip netns exec "$ns" ethtool -K out tx-checksumming off

	if [ -n "$gw" ]; then
		ip -n "$ns" route add "$gw" dev out scope link
		ip -n "$ns" route add default via "$gw"
	fi
}

case "$1" in
	start) _start ;;
	xdp)   _xdp   ;;
	stop)  _stop  ;;
	run)   _run   ;;
	*)     _usage ;;
esac
