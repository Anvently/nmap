# ft_nmap

A partial reimplementation of [Nmap](https://nmap.org/) in C, built on raw sockets and multithreading. Supports the most common scan types, dynamic RTT estimation via ICMP/TCP ping, and packet-level tracing.

> Requires root privileges to craft raw packets (except for connect scan).

---

## Features

- **Scan types**: SYN, ACK, NULL, FIN, Xmas, Connect, UDP
- **Host discovery**: DNS resolution + ICMP/TCP ping to confirm host is up and compute a dynamic RTT used as scan timeout
- **Multithreaded**: up to 250 threads, each handling multiple ports asynchronously — TCP ports are scanned concurrently, and a UDP scan can run in parallel with a TCP scan on the same host
- **Packet tracing**: print every sent/received packet with full header details (`--trace-packet`)
- **Verbosity**: detailed per-port results with state, service name, and reason
- **Packet crafting**: custom TTL, source port, MTU fragmentation, source address spoofing, hex payload

---

## Scan Types

| Scan      | Description |
|-----------|-------------|
| `SYN`     | Half-open scan. Sends a SYN, waits for SYN-ACK (open) or RST (closed). Never completes the handshake. Stealthy, fast, and the most common scan type. |
| `ACK`     | Does not determine open/closed — used to map firewall rules. An unfiltered port responds with RST; no response means filtered. |
| `NULL`    | Sends a packet with no TCP flags set. Open/filtered ports do not respond; closed ports reply with RST. |
| `FIN`     | Sends only the FIN flag. Same response logic as NULL. Can bypass some stateless firewalls. |
| `Xmas`    | Sets FIN, PSH, and URG flags. Same logic as NULL/FIN. Named after a "lit-up" packet. |
| `Connect` | Full TCP handshake via the OS `connect()` syscall. Does not require root, but is easily logged. |
| `UDP`     | Sends a UDP packet. Closed ports reply with ICMP port-unreachable; open ports may respond or stay silent. Slower and less reliable than TCP scans. |

### Port States

| State             | Meaning |
|-------------------|---------|
| `open`            | A service is actively accepting connections |
| `closed`          | Port is reachable but no service is listening |
| `filtered`        | A firewall or filter is blocking the probe — no response or ICMP unreachable |
| `open\|filtered`  | Cannot determine if open or filtered (common with UDP, NULL, FIN, Xmas) |
| `unfiltered`      | Port is reachable but state is undetermined (ACK scan) |

---

## Build

```bash
make
```

---

## Usage

```
Usage: ft_nmap [OPTION...] HOST ...
Scan host port and more.

  -e, --interface               use specified interface
  -n, --numeric                 never do DNS resolution
      --ttl=N                   set IP time-to-live to N (default: 64)
  -g, --source-port=N           use N as source port
  -v, --verbose                 verbose output
      --data=PATTERN            fill payloads with given hex pattern
  -r, --sequential              scan ports in user-specified order (no randomization)
  -f, --mtu=NUMBER              fragment packets with given MTU
  -S, --usurp=ADDRESS           spoof source IP address
      --sim-ports=NUMBER        max number of ports being scan simultaneously for a single host. Default to 16.
      --open                    only display open or potentially open ports
      --rtt-factor=FACTOR       port timeout = last RTT × factor (default: 10.0)
      --rtt-max=MAX             maximum probe timeout in ms (default: 3000.0)
      --skip-ping               skip host discovery, treat all hosts as online
  -L, --list                    only list hosts that responded to ping, skip port scan
  -N, --no-service              do not resolve service names
      --trace-packet            print every packet sent and received
  -p, --port=[PORT,MIN-MAX,...] ports to scan — individual or ranges (default: 1-1024)
  -t, --threads=N               max threads to use, 1–250 (default: 16)
  -s, --scan=[LIST,...]         scan types to run (default: all)
      --file=FILE               read hostnames from file
  -?, --help                    show help
```

---

## Examples

### Basic SYN scan

```bash
sudo ./ft_nmap scanme.nmap.org --scan SYN -p 22,80,443
```

### Multiple scan types with verbosity

```bash
sudo ./ft_nmap google.com --scan SYN,UDP -p 1-1024 -v --reason
```

### Full packet trace

```bash
sudo ./ft_nmap google.com --trace-packet --scan SYN -p 80,443,75 -v
```

Sample output:
```
DNS scan started, host google.com
[9647] success: DNS resolution for host google.com: 172.217.20.46 (par10s09-in-f46.1e100.net)
Scan done, host google.com
DNS: success, 172.217.20.46 (par10s09-in-f46.1e100.net)
PING scan started, host google.com
[9648] SND TCP 10.14.8.1:55573 > 172.217.20.46:80 S ttl=64 id=436 iplen=40 seq=2852913152 win=1024
[9648] SND ICMP [10.14.8.1 > 172.217.20.46 ECHO (type=8/code=0) id=9648 seq=0] IP [ttl=64, id=63349, iplen=28]
[9648] RCV ICMP [172.217.20.46 > 10.14.8.1 ECHO REPLY (type=0/code=0) id=9648 seq=0] IP [ttl=116, id=0, iplen=28]
Scan done, host google.com
PING: UP, 1/5 port, reason: icmp reply (ttl = 116, rtt = 1.01 ms)
SYN scan started, host google.com
[9649] SND TCP 10.14.8.1:57449 > 172.217.20.46:75 S ttl=64 id=50087 iplen=40 seq=2005663744 win=1024
[9649] SND TCP 10.14.8.1:57449 > 172.217.20.46:80 S ttl=64 id=22250 iplen=40 seq=3759996928 win=1024
[9649] SND TCP 10.14.8.1:57449 > 172.217.20.46:443 S ttl=64 id=11587 iplen=40 seq=2048196608 win=1024
[9649] RCV TCP 172.217.20.46:443 > 10.14.8.1:57449 SA ttl=119 id=0 iplen=44 seq=1988261667 win=65535
[9649] RCV TCP 172.217.20.46:80 > 10.14.8.1:57449 SA ttl=119 id=0 iplen=44 seq=1592777102 win=65535
Scan done, host google.com
SYN: 3 ports
PORT      STATE           SERVICE         REASON          ERROR
75/tcp    filtered        priv-dial       no response
80/tcp    open            http            syn_ack ttl 119
443/tcp   open            https           syn_ack ttl 119
```

### Spoof source address and fragment packets

```bash
sudo ./ft_nmap target.host --scan SYN -S 192.168.1.1 -f 8 -p 1-1024
```

### Scan from a host list

```bash
sudo ./ft_nmap --file hosts.txt --scan SYN,FIN,UDP -p 20-1024 -t 50
```

---

## Notes

- **NULL, FIN, and Xmas scans** are unreliable against Windows hosts — Windows sends RST regardless of port state, making every port appear closed.
- **UDP scanning** is inherently slower: open UDP ports often don't reply at all, so the scanner must wait for the full RTT-based timeout before marking a port as `open|filtered`.
- **SYN scan** is the default in real Nmap for a reason — it's fast, reliable, and doesn't complete the TCP handshake, reducing the chance of being logged by the application layer.
- Port randomization is enabled by default to reduce the chance of triggering rate-limiting or IDS signatures; use `-r` to disable it.
- The dynamic RTT computed during the ping phase is used to calibrate per-probe timeouts, reducing both false `filtered` results and unnecessary wait time.

---

## Implementation

See [nmap_architecture.md](./nmap_architecture.md).

## Legal

Only scan hosts you own or have explicit permission to scan. Unauthorized port scanning may be illegal depending on your jurisdiction.