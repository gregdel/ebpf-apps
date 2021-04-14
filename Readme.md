# XDP Apps

# Foward XDP

Start the lab.

```sh
./labs/forward.sh
```

Attach the XDP program in the forwarding namespace.

```sh
sudo ip netns exec lab-fwd ./forward-xdp
```

In case of a veth, we need to link a dummy XDP program on the peer interface.

```sh
sudo ip link set lab-fwd-br xdp object .output/forward-xdp.bpf.o section xdp_dummy
```
