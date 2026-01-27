"""Validate IP addresses, ports, and patterns for nftfw database editor.

This module provides validation functions for user input in the nftfwedit utility
and other database editing tools. It validates IP addresses, port specifications,
and pattern names to ensure they are in the correct format before being stored
in the nftfw blacklist database.

**Validation Functions:**

validate_and_return_ip(ipstr)
    Validates and normalises a single IP address or network. Handles both IPv4
    and IPv6 addresses in various formats, including CIDR notation. Strips
    .auto suffix and converts | to / for CIDR notation.

validate_and_return_ip_list(iplist)
    Validates a list of IP addresses, returning only the valid ones. Useful
    for batch operations.

validate_port(ports)
    Validates port specifications which can be:
        - The string "all" for all ports
        - Numeric port numbers (1-65535)
        - Service names from /etc/services (e.g., "ssh", "http")
        - Comma-separated list of ports and/or service names

validate_pattern(pattern)
    Validates pattern names used in the blacklist system. Pattern names must
    not contain spaces or commas.

**Input Formats:**

IP Addresses:
    - Standard notation: "192.168.1.1" or "2001:db8::1"
    - CIDR notation: "192.168.1.0/24" or "2001:db8::/32"
    - File format with |: "192.168.1.0|24" (converted to /)
    - Auto suffix: "192.168.1.1.auto" (suffix removed)

Ports:
    - Special value: "all"
    - Numeric: "22", "80", "443"
    - Service name: "ssh", "http", "https"
    - Multiple: "22,80,443" or "ssh,http,https"

Patterns:
    - Simple names: "sshd", "apache", "postfix"
    - No spaces or commas allowed

**Related Modules:**
    - nftfwedit: Main database editor utility that uses these validators
    - fwdb: Database module that stores validated IP addresses
    - blacklist: Uses patterns for log file matching

Example:
    Validate an IP address::

        ip = validate_and_return_ip("192.168.1.0/24")
        if ip:
            print(f"Valid IP: {ip}")
        else:
            print("Invalid IP address")

    Validate ports::

        valid, result = validate_port("ssh,http,443")
        if valid:
            print(f"Port list: {result}")  # [22, 80, 443]
        else:
            print(f"Error: {result}")

    Validate pattern name::

        valid, result = validate_pattern("sshd-scanner")
        if valid:
            print(f"Valid pattern: {result}")
        else:
            print(f"Error: {result}")
"""
from __future__ import annotations

import ipaddress
import socket
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

log = logging.getLogger('nftfw')

def validate_and_return_ip(ipstr: str) -> str | None:
    """Validate and normalise an IP address or network.

    Validates user-provided IP addresses and converts them to canonical form
    for storage in the nftfw database. Handles multiple input formats:

    **Input Format Handling:**

    .auto suffix
        Automatically stripped (e.g., "192.168.1.1.auto" → "192.168.1.1")
        The .auto suffix is used in filename format but not in database

    Pipe notation
        Converted to slash (e.g., "192.168.1.0|24" → "192.168.1.0/24")
        The pipe notation is used in filenames where / is not allowed

    CIDR notation
        Validated and normalised (e.g., "192.168.1.5/24" → "192.168.1.0/24")
        Uses strict=False to allow host bits in network specification

    Plain addresses
        IPv4 and IPv6 validated (e.g., "192.168.1.1", "2001:db8::1")

    **Error Handling:**

    Invalid addresses are logged as errors and None is returned. This allows
    the caller to decide how to handle validation failures.

    Args:
        ipstr: IP address string in any supported format

    Returns:
        Canonical string representation of the IP address or network,
        or None if validation fails

    Example:
        Validate various IP formats::

            # Plain IPv4
            ip = validate_and_return_ip("192.168.1.1")
            # Returns: "192.168.1.1"

            # CIDR notation
            ip = validate_and_return_ip("192.168.1.0/24")
            # Returns: "192.168.1.0/24"

            # File format with pipe
            ip = validate_and_return_ip("192.168.1.0|24")
            # Returns: "192.168.1.0/24"

            # Auto suffix
            ip = validate_and_return_ip("192.168.1.1.auto")
            # Returns: "192.168.1.1"

            # IPv6
            ip = validate_and_return_ip("2001:db8::1")
            # Returns: "2001:db8::1"

            # Invalid input
            ip = validate_and_return_ip("not-an-ip")
            # Returns: None (and logs error)
    """
    if '.auto' in ipstr:
        ipstr = ipstr.replace('.auto', '')

    # see if the user has used the | form
    if '|' in ipstr:
        ipstr = ipstr.replace('|', '/')

    try:
        i: IPv4Address | IPv4Network | IPv6Address | IPv6Network
        if '/' in ipstr:
            i = ipaddress.ip_network(ipstr, strict=False)
        else:
            i = ipaddress.ip_address(ipstr)
        return str(i)
    except ValueError as e:
        log.error('Problem with %s: %s', ipstr, str(e))
        return None

def validate_and_return_ip_list(iplist: list[str]) -> list[str]:
    """Validate a list of IP addresses.

    Validates multiple IP addresses in batch, filtering out invalid entries.
    Each IP address is validated using validate_and_return_ip(), which handles
    all supported input formats (.auto suffix, pipe notation, CIDR, etc.).

    **Behaviour:**

    - Valid addresses are included in the output list
    - Invalid addresses are silently skipped (errors logged by validate_and_return_ip)
    - Empty input list returns empty output list
    - Order of valid addresses is preserved

    This is useful for batch operations where you want to process as many valid
    addresses as possible even if some are invalid.

    Args:
        iplist: List of IP address strings in any supported format

    Returns:
        List of validated IP address strings in canonical form.
        Empty list if no addresses are valid.

    Example:
        Validate multiple addresses::

            addresses = [
                "192.168.1.1",
                "invalid-ip",
                "10.0.0.0/8",
                "192.168.1.1.auto",
                "2001:db8::1"
            ]
            valid = validate_and_return_ip_list(addresses)
            # Returns: ["192.168.1.1", "10.0.0.0/8", "192.168.1.1", "2001:db8::1"]
            # Note: "invalid-ip" was skipped

        Handle empty or all-invalid input::

            empty = validate_and_return_ip_list([])
            # Returns: []

            bad = validate_and_return_ip_list(["not-ip", "also-bad"])
            # Returns: []
    """
    out: list[str] = []
    for ip in iplist:
        ret = validate_and_return_ip(ip)
        if ret is not None:
            out.append(ret)
    return out

def validate_port(ports: str) -> tuple[bool, str | list[int]]:
    """Validate a port string supplied by the user.

    Validates port specifications which can be numeric port numbers, service
    names from /etc/services, or comma-separated combinations. Returns either
    the special value "all" or a deduplicated, sorted list of port numbers.

    **Supported Formats:**

    Special value
        "all" - Matches all ports (returned as string "all")

    Numeric ports
        "22", "80", "443" - Port numbers 1-65535

    Service names
        "ssh", "http", "https" - Looked up in /etc/services

    Multiple values
        "22,80,443" - Comma-separated list (duplicates removed)
        "ssh,http,https" - Service names in list
        "22,http,443" - Mix of numbers and names

    **Processing:**

    - Leading/trailing whitespace is stripped
    - Commas separate multiple values
    - Empty strings between commas are ignored ("22,,80" → [22, 80])
    - Service names resolved to port numbers via socket.getservbyname()
    - Output list is sorted and deduplicated
    - If "all" appears, immediately returns (True, "all")

    Args:
        ports: Port specification string

    Returns:
        Tuple of (success, result):
            - (True, "all") if ports is "all"
            - (True, [port_numbers]) if valid - sorted list of unique integers
            - (False, error_message) if invalid - string describing the error

    Example:
        Validate various port formats::

            # Special value
            valid, result = validate_port("all")
            # Returns: (True, "all")

            # Single numeric port
            valid, result = validate_port("22")
            # Returns: (True, [22])

            # Service name
            valid, result = validate_port("ssh")
            # Returns: (True, [22])

            # Multiple ports (deduplicated and sorted)
            valid, result = validate_port("443,80,22,80")
            # Returns: (True, [22, 80, 443])

            # Mix of numbers and service names
            valid, result = validate_port("ssh,80,https")
            # Returns: (True, [22, 80, 443])

            # Invalid service name
            valid, result = validate_port("nonexistent-service")
            # Returns: (False, "Unknown service name found: nonexistent-service")

            # Empty input
            valid, result = validate_port("")
            # Returns: (False, "Ports cannot be empty")
    """
    ports = ports.strip()
    if not any(ports):
        return False, 'Ports cannot be empty'
    plist = (l.strip() for l in ports.split(','))
    slist = (l for l in plist if l != '')
    out: list[int] = []
    for p in slist:
        if p == 'all':
            return True, 'all'
        try:
            pi: int = int(p)
            out.append(pi)
        except ValueError:
            try:
                pi = socket.getservbyname(p)
                out.append(pi)
            except OSError:
                return False, f'Unknown service name found: {p}'
    # make ordered list with no duplicates
    # ports are already ints
    ordered: list[int] = sorted(list(set(out)))
    return True, ordered

def validate_pattern(pattern: str) -> tuple[bool, str]:
    """Validate a pattern supplied by the user.

    Validates pattern names used in the nftfw blacklist system. Pattern names
    identify which pattern file was used to match log entries. They must be
    simple identifiers without spaces or commas.

    **Validation Rules:**

    - Cannot be empty (after stripping whitespace)
    - Cannot contain spaces
    - Cannot contain commas

    These restrictions ensure pattern names can be safely used in:
        - Database storage (patterns are stored as simple strings)
        - Command-line arguments (spaces would cause parsing issues)
        - Log messages (commas would interfere with CSV-style logging)

    **Common Pattern Names:**

    Valid examples: "sshd", "apache", "postfix", "dovecot", "sshd-scan"

    Args:
        pattern: Pattern name string to validate

    Returns:
        Tuple of (success, result):
            - (True, pattern) if valid - stripped pattern name
            - (False, error_message) if invalid - string describing the error

    Example:
        Validate pattern names::

            # Valid pattern
            valid, result = validate_pattern("sshd")
            # Returns: (True, "sshd")

            # Valid with hyphen
            valid, result = validate_pattern("sshd-scanner")
            # Returns: (True, "sshd-scanner")

            # Whitespace is stripped
            valid, result = validate_pattern("  postfix  ")
            # Returns: (True, "postfix")

            # Invalid: contains space
            valid, result = validate_pattern("ssh d")
            # Returns: (False, "Pattern cannot contain spaces or commas")

            # Invalid: contains comma
            valid, result = validate_pattern("sshd,apache")
            # Returns: (False, "Pattern cannot contain spaces or commas")

            # Invalid: empty
            valid, result = validate_pattern("")
            # Returns: (False, "Pattern cannot be empty")

            # Invalid: only whitespace
            valid, result = validate_pattern("   ")
            # Returns: (False, "Pattern cannot be empty")
    """
    pattern = pattern.strip()
    if not any(pattern):
        return False, 'Pattern cannot be empty'
    if ',' in pattern \
       or ' ' in pattern:
        return False, 'Pattern cannot contain spaces or commas'
    return True, pattern
