#!/usr/bin/env python3
"""A bounded TCP connect scanner for authorized network checks."""

from __future__ import annotations

import argparse
import ipaddress
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable


DEFAULT_PORTS = "22,80,443,8080"
MAX_HOSTS = 256
MAX_PORTS = 128
MAX_WORKERS = 64


class ScanInputError(ValueError):
    """Raised when scan input is invalid or outside the configured scope."""


def parse_ports(spec: str) -> list[int]:
    """Parse comma-separated ports and inclusive ranges."""
    ports: set[int] = set()
    if not spec.strip():
        raise ScanInputError("At least one TCP port is required.")

    try:
        for part in spec.split(","):
            part = part.strip()
            if not part:
                raise ScanInputError("Empty item in port list.")
            if "-" in part:
                pieces = part.split("-")
                if len(pieces) != 2:
                    raise ScanInputError(f"Invalid port range: {part}")
                start, end = (int(piece) for piece in pieces)
                if start > end:
                    raise ScanInputError(f"Port range must ascend: {part}")
                values: Iterable[int] = range(start, end + 1)
            else:
                values = (int(part),)

            for port in values:
                if not 1 <= port <= 65535:
                    raise ScanInputError(f"Port out of range: {port}")
                ports.add(port)
                if len(ports) > MAX_PORTS:
                    raise ScanInputError(f"Limit is {MAX_PORTS} distinct ports.")
    except ValueError as exc:
        if isinstance(exc, ScanInputError):
            raise
        raise ScanInputError("Ports must be numbers or ranges, e.g. 22,80,8000-8010.") from exc

    return sorted(ports)


def resolve_targets(target: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Expand an IP/CIDR or resolve a hostname, with a strict host-count cap."""
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError:
        try:
            answers = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise ScanInputError(f"Could not resolve target: {target}") from exc
        addresses = sorted({ipaddress.ip_address(item[4][0]) for item in answers}, key=lambda ip: (ip.version, int(ip)))
    else:
        if network.num_addresses > MAX_HOSTS:
            raise ScanInputError(
                f"Network contains {network.num_addresses} addresses; limit is {MAX_HOSTS}."
            )
        addresses = list(network.hosts()) if network.prefixlen < network.max_prefixlen else [network.network_address]

    if not addresses:
        raise ScanInputError("No usable addresses found for target.")
    if len(addresses) > MAX_HOSTS:
        raise ScanInputError(f"Resolved target exceeds the {MAX_HOSTS}-host limit.")
    return addresses


def validate_scope(
    addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address],
    allow_public: bool = False,
) -> None:
    """Reject public/reserved destinations unless the user explicitly acknowledges scope."""
    for address in addresses:
        if address.is_multicast or address.is_unspecified or address.is_reserved:
            raise ScanInputError(f"Destination {address} is not an allowed unicast target.")
        if address.is_global and not allow_public:
            raise ScanInputError(
                f"{address} is a public address. Use --allow-public only when you are "
                "authorized to assess this system."
            )


def check_port(address: str, port: int, timeout: float) -> bool:
    """Return True only when a TCP connection succeeds."""
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as connection:
            connection.settimeout(timeout)
            return connection.connect_ex((address, port)) == 0
    except OSError:
        return False


def scan_host(address: str, ports: list[int], timeout: float, workers: int) -> list[int]:
    """Scan one host concurrently and return open TCP ports."""
    open_ports: list[int] = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        jobs = {
            executor.submit(check_port, str(address), port, timeout): port
            for port in ports
        }
        for job in as_completed(jobs):
            if job.result():
                open_ports.append(jobs[job])
    return sorted(open_ports)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan selected TCP ports on systems you own or are authorized to assess."
    )
    parser.add_argument("target", help="IP address, CIDR network (up to 256 addresses), or hostname")
    parser.add_argument(
        "--ports", default=DEFAULT_PORTS,
        help=f"Comma-separated ports and ranges (default: {DEFAULT_PORTS}; max {MAX_PORTS} distinct ports)",
    )
    parser.add_argument("--timeout", type=float, default=0.5, help="Connection timeout in seconds (0.1-5)")
    parser.add_argument("--workers", type=int, default=16, help=f"Concurrent connections (1-{MAX_WORKERS})")
    parser.add_argument(
        "--allow-public", action="store_true",
        help="Acknowledge that public targets are in scope and explicitly authorized",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not 0.1 <= args.timeout <= 5:
        parser.error("--timeout must be between 0.1 and 5 seconds.")
    if not 1 <= args.workers <= MAX_WORKERS:
        parser.error(f"--workers must be between 1 and {MAX_WORKERS}.")

    try:
        ports = parse_ports(args.ports)
        addresses = resolve_targets(args.target)
        validate_scope(addresses, allow_public=args.allow_public)
    except ScanInputError as exc:
        parser.error(str(exc))

    print(f"Target: {args.target}")
    print("Resolved addresses: " + ", ".join(str(address) for address in addresses))
    print("Ports: " + ",".join(str(port) for port in ports))
    print(f"Scanning {len(addresses)} host(s) with {len(ports)} port(s)...")

    total_open = 0
    for address in addresses:
        open_ports = scan_host(address, ports, args.timeout, args.workers)
        print(f"\n{address}")
        if open_ports:
            for port in open_ports:
                print(f"  {port}/tcp open")
            total_open += len(open_ports)
        else:
            print("  No open TCP ports found in the selected port list.")

    print(f"\nScan complete. {total_open} open port(s) found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
