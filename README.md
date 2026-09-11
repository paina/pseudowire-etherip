# pseudowire-etherip

A DPDK application that extends an L2 segment over EtherIP (RFC 3378)
tunnels, over either IPv4 or IPv6.

It is derived from ginzado-pseudowire
(<https://github.com/ginzado/dpdk>), replacing its proprietary
encapsulation with standard EtherIP (IP protocol number 97). The peer
therefore does not have to be this application: any implementation that
speaks EtherIP (the gif/etherip interfaces of BSD-derived operating
systems, router products from various vendors, ...) will interoperate.

* EtherIP over IPv4 (`ip4` mode)
* EtherIP over IPv6 (`ip6` mode)

The application uses two ports. Frames received on the DL (downlink)
port are encapsulated in EtherIP and sent out of the UL (uplink) port;
EtherIP packets received on the UL port are decapsulated and sent out of
the DL port.

> **Status: experimental.** The data plane and control plane have been
> verified against DPDK 25.11 using the `net_pcap` PMD (bit-exact
> RFC 3378 encapsulation, encap/decap round trips including
> fragmentation and reassembly, ARP/NDP next-hop resolution). The
> application has not yet been tested with real NICs and real traffic.

## Differences from ginzado-pseudowire

* The encapsulation is standard EtherIP (RFC 3378), so the peer can be
  any EtherIP implementation.
* Oversized packets are split with standard IP fragmentation (IPv4
  fragments / the IPv6 fragment extension header) instead of a
  proprietary format. Fragmentation and reassembly use DPDK's
  `librte_ip_frag`.
* Tunnels can be built over IPv4 as well as IPv6.
* The next-hop MAC address can be resolved automatically with ARP
  (`ip4`) or NDP (`ip6`), or specified statically in the configuration.

## Encapsulation

The headers prepended on encapsulation are:

### EtherIP over IPv4

| Header                  |    Size |
|:------------------------|--------:|
| Outer Ethernet header   | 14 byte |
| Outer IPv4 header       | 20 byte |
| EtherIP header          |  2 byte |
| Original Ethernet frame |         |

### EtherIP over IPv6

| Header                  |    Size |
|:------------------------|--------:|
| Outer Ethernet header   | 14 byte |
| Outer IPv6 header       | 40 byte |
| EtherIP header          |  2 byte |
| Original Ethernet frame |         |

The EtherIP header is 16 bits: the top 4 bits are the version (3) and
the remaining 12 bits are reserved (0), i.e. a fixed `0x3000`. The outer
IP protocol number (Next Header for IPv6) is 97 (EtherIP).

On receive, packets whose EtherIP version is not 3 are discarded (as
required by RFC 3378).

## Fragmentation and MTU

If an encapsulated packet exceeds the UL-side MTU (configuration key
`mtu`, default 1500), it is split with standard IP fragmentation before
transmission. Fragmented packets received on the UL side are reassembled
before decapsulation.

When passing an inner MTU of 1500 (1514-byte frames) through an outer
MTU of 1500, every full-sized frame is split in two. If the outer path
can carry jumbo frames, raising the MTU on the peer network is
preferable; but where the path MTU cannot be changed (e.g. the
"IPv6 folded-back" connectivity within the NTT FLET'S network in Japan),
fragmentation lets such frames through as-is.

Reassembly has the following constraints (from `librte_ip_frag` and this
implementation):

* At most 8 fragments per packet.
* The IPv6 fragment extension header is only handled when it
  immediately follows the IPv6 header (typical EtherIP implementations
  send it this way).
* IPv4 packets with header options (IHL != 5) are not handled.
* At most 2048 packets can be awaiting reassembly at a time, with a
  timeout of 250 ms.

## Next-hop resolution

The destination of encapsulated packets (the destination MAC address of
the outer Ethernet header) is determined by one of the following. Frames
received on the DL side are discarded until it is resolved.

* If `dstmac` is set in the configuration, that value is always used.
* `ip4` mode: an ARP request for the peer address is sent every second
  and the answer is learned. ARP requests for the local address are
  answered. (This assumes the peer is on-link; if it is off-link,
  specify the gateway's MAC address with `dstmac`.)
* `ip6` mode: an NS and an RS for the peer address are sent every
  second and NAs are learned (when the peer is on-link). As in
  ginzado-pseudowire, when an RA advertising the same prefix as the
  local address is received, the MAC address of its sender (the router)
  is learned (for cases like the NTT FLET'S folded-back connectivity
  where the peer is behind a router). NSes for the local address are
  answered with an NA.

## Building

Requirements:

* DPDK 25.11 LTS (the tested target; DPDK releases older than 24.11
  cannot build it because `struct rte_ipv6_addr` is unavailable)
* meson and ninja
* a C toolchain and pkg-config

On Ubuntu 26.04:

```
$ sudo apt install build-essential meson pkg-config dpdk libdpdk-dev
$ meson setup build
$ meson compile -C build
```

This produces `build/dpdk-pseudowire-etherip` and `build/pestats`.

Alternatively, the application can be compiled directly against an
installed DPDK, like any other out-of-tree DPDK application:

```
$ cc $(pkg-config --cflags libdpdk) -DALLOW_EXPERIMENTAL_API \
	-o dpdk-pseudowire-etherip pseudowire_etherip.c \
	$(pkg-config --libs libdpdk)
```

## Usage

### DPDK setup

Set up hugepages and bind the NICs, as for any DPDK application:

```
% sudo mkdir /dev/hugepages # if needed
% sudo sh -c 'echo 64 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages'
% sudo modprobe uio_pci_generic
% sudo dpdk-devbind.py -u 0000:01:00.0
% sudo dpdk-devbind.py -u 0000:01:00.1
% sudo dpdk-devbind.py -b uio_pci_generic 0000:01:00.0
% sudo dpdk-devbind.py -b uio_pci_generic 0000:01:00.1
```

Two ports are required: port 0 is the DL side (raw Ethernet frames) and
port 1 is the UL side (EtherIP packets).

### Configuration file

Lines 1-3 are, in order, the mode, the peer address (`dstaddr`) and the
local address (`srcaddr`). Lines 4 onward are optional `key value`
settings in any order. Everything after `#` is a comment.

EtherIP over IPv4:

```
ip4           # mode
192.0.2.2     # dstaddr (peer address)
192.0.2.1     # srcaddr (local address)
```

EtherIP over IPv6:

```
ip6                               # mode
3ffe::1                           # dstaddr (peer address)
2001:db8::1                       # srcaddr (local address)
```

As in ginzado-pseudowire, addresses may also be written as plain hex
strings without separators (8 characters for IPv4, 32 for IPv6).

Optional settings:

```
mtu 1500                          # UL-side MTU (ip4: 576-1500, ip6: 1280-1500)
dstmac 00:1a:2b:3c:4d:5e          # static next-hop MAC address
stats /run/pestats.socket         # statistics socket path (read at startup only)
```

### Running

```
$ sudo ./dpdk-pseudowire-etherip -l 1-3 -- --config path/to/config
```

Like ginzado-pseudowire, the application uses three lcores:

* a loop handling packets received on the UL port (`lcore_ul`)
* a loop handling frames received on the DL port (`lcore_dl`)
* a loop handling everything else — frames to discard, ARP/NDP and so
  on (`lcore_main`)

Sending SIGHUP makes the application reload the configuration file.

### Statistics

The `pestats` command reads statistics from the running application
through a UNIX-domain socket:

```
$ sudo ./pestats
pestats.ul_rx_packets                 27811573
...
```

| Counter             | Meaning                                             |
|:--------------------|:----------------------------------------------------|
| ul_rx_packets/bytes | Packets/bytes received on the UL port               |
| ul_rx_bpdus         | BPDUs found in decapsulated frames                  |
| ul_tx_packets/bytes | Packets/bytes sent out of the UL port               |
| ul_tx_errors        | Packets that could not be sent on the UL port       |
| dl_rx_packets/bytes | Frames/bytes received on the DL port                |
| dl_rx_bpdus         | BPDUs received on the DL port                       |
| dl_tx_packets/bytes | Frames/bytes sent out of the DL port                |
| dl_tx_errors        | Frames that could not be sent on the DL port        |
| encap_frags         | Times a frame was fragmented while encapsulating    |
| decap_reasms        | Times reassembly completed while decapsulating      |
| decap_reasm_drops   | Fragments dropped without being reassembled         |
| encap_noready_drops | Frames dropped with the next hop unresolved         |

The BPDU counters (`ul_rx_bpdus` / `dl_rx_bpdus`) behave the same way as
in ginzado-pseudowire, so they can be used for liveness monitoring in
the same manner as its `check_gpwbpdu.pl`.

## Limitations and caveats

* Only a single peer is supported (packets whose source/destination IP
  addresses do not match the configuration are not treated as tunnel
  packets).
* EtherIP has no keepalive or authentication mechanism. If needed,
  substitute something like monitoring the BPDU counters. There is no
  payload checksum either, so error detection relies on the Ethernet
  FCS, as with ginzado-pseudowire.
* Outer IPv6 packets carrying other extension headers are not handled.
* The three lcores busy-poll at all times.

## License

BSD-3-Clause. See [LICENSE](LICENSE).

* Copyright (c) 2022 Ginzado Co., Ltd.
* Copyright (c) 2026 Taisuke "paina" SATO
