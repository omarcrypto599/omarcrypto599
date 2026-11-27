# Python Network Scanner

A small, defensive TCP connect scanner for learning network fundamentals and checking systems you own or are explicitly authorized to assess.

## Features

- Scans a user-selected list or range of TCP ports.
- Resolves hostnames and accepts IPv4/IPv6 addresses or CIDR networks.
- Uses ordinary TCP connections (no raw sockets, packet crafting, or stealth techniques).
- Limits a CIDR scan to 256 addresses, the port list to 128 entries, and concurrency to 64 workers.
- Restricts scans to private, loopback, and link-local destinations by default.
- Requires an explicit `--allow-public` acknowledgement before scanning public IP addresses.
- Includes unit tests for input validation and destination-scope checks.

## Requirements

- Python 3.10+
- No third-party packages

## Quick start

From this directory:

```bash
python network_scanner.py 127.0.0.1 --ports 22,80,443
python network_scanner.py 192.168.1.10 --ports 1-1024 --timeout 0.4
python network_scanner.py 192.168.1.0/24 --ports 22,80,443 --workers 32
```

To assess a public host, only when you own it or have explicit permission:

```bash
python network_scanner.py example.com --ports 80,443 --allow-public
```

Run the tests:

```bash
python -m unittest -v
```

## Example output

```text
Target: 127.0.0.1
Resolved addresses: 127.0.0.1
Ports: 22,80,443
Scanning 1 host(s) with 3 port(s)...

127.0.0.1
  80/tcp open
  443/tcp closed or filtered
  22/tcp closed or filtered

Scan complete. 1 open port(s) found.
```

Results depend on the host, firewall, network path, and timeout. A port reported as closed or filtered may be blocked or unreachable; this tool does not distinguish those states.

## Responsible use

Use this scanner only on devices and networks you own or have clear, written authorization to test. Do not scan third-party systems, shared networks, or public address ranges without permission. The public-target flag is an acknowledgement, not authorization.

This tool performs TCP connection attempts only. It is not a vulnerability scanner, does not exploit services, and does not identify software versions. Keep scans small and rate-limited, and follow the rules of your network and organization.

## Limitations

- TCP only; UDP and service fingerprinting are out of scope.
- No guarantee that a non-responsive port is closed.
- DNS answers can change between runs.
- The built-in scope checks are safety guardrails, not a substitute for authorization.
