# Wraith

A silent, low-level TUI packet sniffer built in C. No libs, no noise, just raw packets.

![License](https://img.shields.io/badge/license-GPLv2-blue)
![Platform](https://img.shields.io/badge/platform-Linux-green)
![Latest Release](https://img.shields.io/github/v/release/uzairdeveloper223/Wraith)

## Features

- Raw socket capture (`AF_PACKET`, `SOCK_RAW`) — no libpcap
- Manual parsing of Ethernet, IP, TCP, UDP, and ICMP headers
- Extracts source/destination IP, ports, protocol, payload size, TTL
- TCP flag display (SYN, ACK, FIN, RST, PSH, URG)
- Threaded capture with shared lock-protected packet buffer
- ncurses TUI with scrollable, color-coded packet list
- Live stats panel (packet counts per protocol)
- Live traffic map with geo-IP visualization
- Filter packets by IP, port, or protocol
- DNS name resolution on selected packets
- Export captured packets to a text file

## Download

Grab the latest pre-built binary from [Releases](https://github.com/uzairdeveloper223/wraith/releases/latest).

```bash
tar -xzf wraith-<version>-linux-x86_64.tar.gz
sudo install -m755 wraith /usr/local/bin/wraith
```

Or build from source:

```bash
git clone https://github.com/uzairdeveloper223/wraith.git
cd wraith
make
sudo ./wraith
```

## Requirements

- Linux (raw sockets require `AF_PACKET`)
- GCC
- ncurses development headers (`libncurses-dev` or `ncurses-devel`)
- Root privileges (for raw socket access)

## Build

```bash
make
```

## Usage

```bash
sudo ./wraith
```

### Keybindings

| Key | Action |
|---|---|
| `q` | Quit |
| `↑` / `k` | Scroll up |
| `↓` / `j` | Scroll down |
| `PgUp` | Page up |
| `PgDn` | Page down |
| `G` | Resume autoscroll |
| `m` | Toggle live traffic map |
| `f` | Set filter (IP / port / protocol) |
| `c` | Clear filter |
| `e` | Export packets to file |
| `d` | DNS lookup on selected packet |

### Color Coding

| Color | Protocol |
|---|---|
| Green | TCP |
| Cyan | UDP |
| Yellow | ICMP |
| White | Other |

## Project Structure

```
src/
├── main.c       — entry point
├── packet.c/h   — ethernet/IP/TCP/UDP/ICMP parsing
├── buffer.c/h   — thread-safe shared packet buffer
├── capture.c/h  — raw socket setup and capture thread
├── filter.c/h   — packet filtering by IP/port/protocol
├── dns.c/h      — DNS reverse resolution
├── geo.c/h      — geo-IP lookup and caching
├── map.c/h      — live traffic map visualization
├── export.c/h   — export packets to text file
└── ui.c/h       — ncurses TUI
```

## Credits

- [uzairdeveloper223](https://github.com/uzairdeveloper223) — GitHub
- Uzair Mughal
- [uzair.is-a.dev](https://uzair.is-a.dev)
- contact@uzair.is-a.dev
