#!/usr/bin/env python3
"""
Functional test of dpdk-pseudowire-etherip with the net_pcap PMD.

The application (build/dpdk-pseudowire-etherip, or $PE_APP) is run without
NICs, hugepages or root: net_pcap virtual devices play the DL and UL ports,
fed from pcap files this script writes, and what the application sends is
compared byte for byte with what RFC 3378 prescribes. The statistics are read
through the pestats socket as well.

Requirements: DPDK with the net_pcap PMD, three CPU cores (lcores 0-2 are
used), about 512 MB of free memory, Python 3 (standard library only).

Usage: tests/pwtest.py [substring]    only the scenarios whose name contains it
"""
import ipaddress, os, re, shutil, socket, struct, subprocess, sys, tempfile, time

APP = os.environ.get("PE_APP", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                            "..", "build", "dpdk-pseudowire-etherip"))
NEXTHOP = bytes.fromhex("001a2b3c4d5e")
V4 = ("192.0.2.2", "192.0.2.1")      # remote, local
V6 = ("2001:db8::2", "2001:db8::1")
# struct pestats, in order
STATS = ["ul_rx_packets", "ul_rx_bytes", "ul_rx_bpdus", "ul_tx_packets", "ul_tx_bytes", "ul_tx_errors",
         "dl_rx_packets", "dl_rx_bytes", "dl_rx_bpdus", "dl_tx_packets", "dl_tx_bytes", "dl_tx_errors",
         "encap_frags", "decap_reasms", "decap_reasm_drops", "encap_noready_drops"]
T = None       # working directory, set in main()
SOCK = None    # statistics socket path

# ---------------------------------------------------------------- packets and pcap files

def pcap_write(path, pkts):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(pkts):
            f.write(struct.pack("<IIII", i + 1, 0, len(p), len(p)) + p)

def pcap_read(path):
    """Packets of a pcap file; an absent or empty file (nothing was ever written) is no packets."""
    if not os.path.exists(path):
        return []
    data = open(path, "rb").read()
    if len(data) < 24:
        return []
    e = "<" if struct.unpack("<I", data[:4])[0] in (0xa1b2c3d4, 0xa1b23c4d) else ">"
    off, pkts = 24, []
    while off + 16 <= len(data):
        incl = struct.unpack(e + "IIII", data[off:off + 16])[2]; off += 16
        pkts.append(data[off:off + incl]); off += incl
    return pkts

def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def eth(dst, src, etype, payload):
    return dst + src + struct.pack("!H", etype) + payload

def inner_frame(i, size):
    """A size-byte Ethernet frame whose payload depends on i."""
    return eth(bytes.fromhex("0a0b0c0d0e0f"), bytes.fromhex("1a1b1c1d1e1f"), 0x88b5,
               bytes([(i * 7 + j) & 0xff for j in range(size - 14)]))

def packed(fam):
    r, l = (V4 if fam == 4 else V6)
    return ipaddress.ip_address(r).packed, ipaddress.ip_address(l).packed

def etherip(fam, inner, ident):
    """An EtherIP packet from the remote end carrying inner, as it arrives on the UL port."""
    remote, local = packed(fam)
    if fam == 4:
        hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 22 + len(inner), ident, 0, 64, 97, 0, remote, local)
        hdr = hdr[:10] + struct.pack("!H", csum(hdr)) + hdr[12:]
        return eth(bytes.fromhex("02aabbccdd01"), NEXTHOP, 0x0800, hdr + b"\x30\x00" + inner)
    hdr = struct.pack("!IHBB16s16s", 0x60000000, 2 + len(inner), 97, 64, remote, local)
    return eth(bytes.fromhex("02aabbccdd01"), NEXTHOP, 0x86dd, hdr + b"\x30\x00" + inner)

def etherip_frags(fam, inner, ident, chunk):
    """The same EtherIP packet split into IP fragments of chunk payload bytes (chunk % 8 == 0)."""
    assert chunk % 8 == 0
    payload = b"\x30\x00" + inner
    remote, local = packed(fam)
    pkts = []
    for off in range(0, len(payload), chunk):
        part = payload[off:off + chunk]
        more = off + len(part) < len(payload)
        if fam == 4:
            hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(part), ident,
                              (0x2000 if more else 0) | (off // 8), 64, 97, 0, remote, local)
            hdr = hdr[:10] + struct.pack("!H", csum(hdr)) + hdr[12:]
            pkts.append(eth(bytes.fromhex("02aabbccdd01"), NEXTHOP, 0x0800, hdr + part))
        else:
            hdr = struct.pack("!IHBB16s16s", 0x60000000, 8 + len(part), 44, 64, remote, local)
            fh = struct.pack("!BBHI", 97, 0, off | (1 if more else 0), ident)
            pkts.append(eth(bytes.fromhex("02aabbccdd01"), NEXTHOP, 0x86dd, hdr + fh + part))
    return pkts

def check_encap(fam, pkts, ul_mac):
    """The inner frames of the packets sent on the UL port (None for a fragment), or a fault description."""
    remote, local = packed(fam)
    got = []
    for p in pkts:
        if p[:6] != NEXTHOP or p[6:12] != ul_mac:
            return "bad outer Ethernet addresses %s" % p[:12].hex()
        if fam == 4:
            if p[12:14] != b"\x08\x00":
                return "bad ethertype"
            ip = p[14:34]
            if ip[9] != 97 or ip[12:16] != local or ip[16:20] != remote or csum(ip) != 0:
                return "bad outer IPv4 header %s" % ip.hex()
            if struct.unpack("!H", ip[2:4])[0] != len(p) - 14:
                return "bad IPv4 total length"
            if struct.unpack("!H", ip[6:8])[0] & 0x3fff:
                got.append(None)
                continue
            body = p[34:]
        else:
            if p[12:14] != b"\x86\xdd":
                return "bad ethertype"
            ip = p[14:54]
            if ip[6] not in (97, 44) or ip[8:24] != local or ip[24:40] != remote:
                return "bad outer IPv6 header %s" % ip.hex()
            if struct.unpack("!H", ip[4:6])[0] != len(p) - 54:
                return "bad IPv6 payload length"
            if ip[6] == 44:
                got.append(None)
                continue
            body = p[54:]
        if body[:2] != b"\x30\x00":
            return "bad EtherIP header %s" % body[:2].hex()
        got.append(body[2:])
    return got

# ---------------------------------------------------------------- running the application

def read_stats():
    """The statistics, as pestats reads them (the application polls the socket only now and then)."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(30)
    s.connect(SOCK)
    s.send(struct.pack("i", 1))
    data = b""
    while len(data) < 8 * len(STATS):
        chunk = s.recv(8 * len(STATS) - len(data))
        if not chunk:
            break
        data += chunk
    s.close()
    return dict(zip(STATS, struct.unpack("<%dQ" % len(STATS), data)))

def command(roles, opts):
    """The command line: one net_pcap device per role ('UL', 'DL' or 'idle'), then the options."""
    cmd = ["stdbuf", "-oL", APP, "-l", "0-2", "--no-huge", "-m", "512", "--no-pci", "--no-telemetry",
           "--file-prefix", "pwtest", "--log-level", "lib.eal:notice"]
    for n, role in sorted(roles.items()):
        rx = os.path.join(T, "etherip.pcap" if role == "UL" else "frames.pcap")
        cmd.append("--vdev=net_pcap%d,rx_pcap=%s,tx_pcap=%s,tx_pcap=%s" % (
            n, rx, os.path.join(T, "tx%d_q0.pcap" % n), os.path.join(T, "tx%d_q1.pcap" % n)))
    return cmd + ["--"] + opts

def clean():
    for f in os.listdir(T):
        if f.startswith("tx"):
            os.remove(os.path.join(T, f))

results = []

def report(name, faults, out):
    ok = not faults
    print("%s %s" % ("PASS" if ok else "FAIL", name))
    for f in faults:
        print("  FAIL:", f)
    if not ok:
        print("  ---- output ----"); print(out.rstrip()); print("  ----------------")
    results.append(ok)

def dataplane(name, opts, fam, dl, ul_pkts, ul_expect, roles={0: "DL", 1: "UL"},
              expect_ul=(1, "net_pcap1"), expect_dl=(0, "net_pcap0"), encap_count=None, stats=None):
    """Run with frames dl on the DL port and packets ul_pkts on the UL port, and check what comes out."""
    clean()
    pcap_write(os.path.join(T, "frames.pcap"), dl)
    pcap_write(os.path.join(T, "etherip.pcap"), ul_pkts)
    proc = subprocess.Popen(command(roles, opts), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    time.sleep(3)
    faults, got_stats = [], None
    if proc.poll() is None:
        try:
            got_stats = read_stats()
        except Exception as e:
            faults.append("statistics query failed: %s" % e)
    proc.terminate()
    try:
        out = proc.communicate(timeout=10)[0]
    except subprocess.TimeoutExpired:
        proc.kill()
        out = proc.communicate()[0]
    m_ul = re.search(r"^Port UL: (\d+) \((\S+)\) MAC: ((?:[0-9a-f]{2} ?){6})", out, re.M)
    m_dl = re.search(r"^Port DL: (\d+) \((\S+)\) MAC:", out, re.M)
    if not m_ul or not m_dl:
        faults.append("port lines missing (did the application exit early?)")
        return report(name, faults, out)
    if (int(m_ul.group(1)), m_ul.group(2)) != expect_ul:
        faults.append("UL is port %s (%s), expected %s" % (m_ul.group(1), m_ul.group(2), expect_ul))
    if (int(m_dl.group(1)), m_dl.group(2)) != expect_dl:
        faults.append("DL is port %s (%s), expected %s" % (m_dl.group(1), m_dl.group(2), expect_dl))
    ul_mac = bytes.fromhex(m_ul.group(3).replace(" ", ""))
    for n, role in sorted(roles.items()):
        q0 = pcap_read(os.path.join(T, "tx%d_q0.pcap" % n))
        q1 = pcap_read(os.path.join(T, "tx%d_q1.pcap" % n))
        if role == "DL":
            if q0 != ul_expect:
                faults.append("decapsulated output mismatch (%d packets, expected %d)" % (len(q0), len(ul_expect)))
        elif role == "UL":
            got = check_encap(fam, q0, ul_mac)
            if isinstance(got, str):
                faults.append("encapsulated output: " + got)
            elif encap_count is not None:
                if len(got) != encap_count:
                    faults.append("encapsulated output: %d packets, expected %d" % (len(got), encap_count))
            elif got != dl:
                faults.append("encapsulated output mismatch (%d packets, expected %d)" % (len(got), len(dl)))
        elif q0 or q1:
            faults.append("net_pcap%d is not in use but sent packets" % n)
    if stats and got_stats:
        for k, v in stats.items():
            if got_stats[k] != v:
                faults.append("statistics: %s = %d, expected %d" % (k, got_stats[k], v))
    report(name, faults, out)

def exits(name, opts, roles={0: "DL", 1: "UL"}, expect_err=None, expect_help=False):
    """Run expecting the application to exit by itself, with the given error message or the usage."""
    clean()
    pcap_write(os.path.join(T, "frames.pcap"), [inner_frame(0, 60)])
    pcap_write(os.path.join(T, "etherip.pcap"), [etherip(4, inner_frame(0, 60), 1)])
    faults = []
    try:
        r = subprocess.run(command(roles, opts), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           text=True, timeout=20)
        out = r.stdout
        if expect_help:
            if r.returncode != 0:
                faults.append("exit status %d, expected 0" % r.returncode)
            if "Usage:" not in out:
                faults.append("usage text missing")
        else:
            if r.returncode == 0:
                faults.append("exit status 0, expected an error")
            if expect_err not in out:
                faults.append("expected message not found: %r" % expect_err)
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or "") if isinstance(e.stdout, str) else ""
        faults.append("the application kept running")
    report(name, faults, out)

# ---------------------------------------------------------------- scenarios

def main():
    global T, SOCK
    only = sys.argv[1] if len(sys.argv) > 1 else None
    if not os.access(APP, os.X_OK):
        sys.exit("application not found: %s (build it, or set PE_APP)" % APP)
    T = tempfile.mkdtemp(prefix="pwtest.")
    SOCK = os.path.join(T, "s.sock")

    def scenario(fn, name, *a, **k):
        if only is None or only in name:
            fn(name, *a, **k)

    base = {4: ["--remote", V4[0], "--local", V4[1], "--nexthop-mac", "00:1a:2b:3c:4d:5e", "--stats-socket", SOCK],
            6: ["--remote", V6[0], "--local", V6[1], "--nexthop-mac", "00:1a:2b:3c:4d:5e", "--stats-socket", SOCK]}

    # -- data plane, both address families
    for fam in (4, 6):
        dl = [inner_frame(i, s) for i, s in enumerate([60, 100, 500, 1000, 1458])]
        ul = [inner_frame(10 + i, s) for i, s in enumerate([60, 200, 1000, 1400])]
        scenario(dataplane, "IPv%d basic, both directions" % fam, base[fam], fam, dl,
                 [etherip(fam, f, 100 + i) for i, f in enumerate(ul)], ul,
                 stats={"ul_rx_packets": 4, "dl_tx_packets": 4, "dl_rx_packets": 5, "ul_tx_packets": 5,
                        "encap_frags": 0, "decap_reasms": 0, "ul_tx_errors": 0, "dl_tx_errors": 0})
        dl = [inner_frame(i, 100 + i) for i in range(40)]
        ul = [inner_frame(100 + i, 100 + i) for i in range(40)]
        scenario(dataplane, "IPv%d burst of 40 each way (more than one receive call)" % fam, base[fam], fam, dl,
                 [etherip(fam, f, 200 + i) for i, f in enumerate(ul)], ul,
                 stats={"ul_rx_packets": 40, "dl_tx_packets": 40, "dl_rx_packets": 40, "ul_tx_packets": 40})
        a, b = inner_frame(1, 1458), inner_frame(2, 3000)
        chunk = 512 if fam == 4 else 1232
        fa, fb = etherip_frags(fam, a, 300, chunk), etherip_frags(fam, b, 301, chunk)
        scenario(dataplane, "IPv%d reassembly of two fragmented packets" % fam, base[fam], fam,
                 [inner_frame(0, 60)], fa + fb, [a, b],
                 stats={"ul_rx_packets": len(fa) + len(fb), "decap_reasms": 2, "decap_reasm_drops": 0,
                        "dl_tx_packets": 2})
        inter = [p for pair in zip(fa, fb) for p in pair] + fa[len(fb):] + fb[len(fa):]
        scenario(dataplane, "IPv%d reassembly with the fragments of two packets interleaved" % fam, base[fam], fam,
                 [inner_frame(0, 60)], inter, [a, b] if len(fa) <= len(fb) else [b, a],
                 stats={"ul_rx_packets": len(inter), "decap_reasms": 2, "dl_tx_packets": 2})
        big = [inner_frame(3, 3000), inner_frame(4, 8978 if fam == 4 else 8958)]
        scenario(dataplane, "IPv%d --mtu 9000, jumbo frames both ways" % fam, base[fam] + ["--mtu", "9000"],
                 fam, big, [etherip(fam, f, 400 + i) for i, f in enumerate(big)], big,
                 stats={"ul_rx_packets": 2, "dl_tx_packets": 2, "ul_tx_packets": 2, "encap_frags": 0})
    scenario(dataplane, "IPv4 --mtu 1400: a 1458-byte frame is fragmented in two", base[4] + ["--mtu", "1400"], 4,
             [inner_frame(5, 1458)], [etherip(4, inner_frame(6, 60), 500)], [inner_frame(6, 60)],
             encap_count=2, stats={"encap_frags": 1, "ul_tx_packets": 2})
    scenario(dataplane, "IPv4 hex address forms", ["--remote=c0000202", "--local=c0000201",
             "--nexthop-mac", "001a2b3c4d5e", "--stats-socket", SOCK], 4,
             [inner_frame(7, 60)], [etherip(4, inner_frame(8, 60), 600)], [inner_frame(8, 60)])

    # -- port selection
    dl, ul = [inner_frame(0, 100)], [inner_frame(1, 100)]
    scenario(dataplane, "ports swapped with --ul-port and --dl-port by name", base[4] + ["--ul-port", "net_pcap0",
             "--dl-port", "net_pcap1"], 4, dl, [etherip(4, ul[0], 1)], ul,
             roles={0: "UL", 1: "DL"}, expect_ul=(0, "net_pcap0"), expect_dl=(1, "net_pcap1"))
    scenario(dataplane, "ports swapped with --ul-port alone (DL is the remaining port)", base[4] + ["--ul-port=0"], 4,
             dl, [etherip(4, ul[0], 1)], ul,
             roles={0: "UL", 1: "DL"}, expect_ul=(0, "net_pcap0"), expect_dl=(1, "net_pcap1"))
    scenario(dataplane, "three ports with both given, the middle one untouched", base[4] + ["--ul-port=net_pcap0",
             "--dl-port=2"], 4, dl, [etherip(4, ul[0], 1)], ul,
             roles={0: "UL", 1: "idle", 2: "DL"}, expect_ul=(0, "net_pcap0"), expect_dl=(2, "net_pcap2"))
    scenario(exits, "error: three ports without both port options", base[4] + ["--ul-port=net_pcap0"],
             roles={0: "UL", 1: "idle", 2: "DL"}, expect_err="number of ports must be 2 (3 found)")
    scenario(exits, "error: the same port for both sides", base[4] + ["--ul-port=0", "--dl-port=0"],
             expect_err="UL and DL ports must differ")
    scenario(exits, "error: unknown port name", base[4] + ["--dl-port", "net_pcap9"],
             expect_err="DL port not found: net_pcap9")

    # -- options
    scenario(exits, "--help", ["--help"], expect_help=True)
    scenario(exits, "error: no options", [], expect_err="--remote and --local are required")
    scenario(exits, "error: address families differ", ["--remote", V4[0], "--local", V6[1]],
             expect_err="must be of the same address family")
    scenario(exits, "error: bad remote address", ["--remote", "192.0.2.300", "--local", V4[1]],
             expect_err="remote address invalid: 192.0.2.300")
    scenario(exits, "error: IPv4 mtu below 576", base[4] + ["--mtu", "575"], expect_err="mtu out of range (576-9000)")
    scenario(exits, "error: IPv6 mtu below 1280", base[6] + ["--mtu", "1279"], expect_err="mtu out of range (1280-9000)")
    scenario(exits, "error: mtu above 9000", base[4] + ["--mtu", "9001"], expect_err="mtu out of range (576-9000)")
    scenario(exits, "error: bad next-hop MAC", base[4][:4] + ["--nexthop-mac", "00:1a:2b:3c:4d"],
             expect_err="next-hop MAC address invalid")
    scenario(exits, "error: the removed --config option", base[4] + ["--config", "x"], expect_err="Usage:")

    print("\n%d/%d passed" % (sum(results), len(results)))
    if all(results):
        shutil.rmtree(T)
    else:
        print("files left in %s" % T)
    sys.exit(0 if all(results) else 1)

if __name__ == "__main__":
    main()
