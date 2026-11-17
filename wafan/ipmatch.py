"""Encoding the @ipMatch operator's argument as a regular expression."""

from __future__ import annotations

import ipaddress

#regex for 1 octet of IPv4 address (number 0-255)
ANY_OCTET_REGEX = "(" + "[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]" + ")"

def octet_range_regex(lowest: int, highest: int) -> str:
    """Creates and returns a regex for number range lowest-highest, where the this range represents a range somewhere in 0-255."""

    #adding all the numbers in the range to the regex
    # TODO - optimization later (creates large regexes)
    regex = str(lowest)
    for num in range(lowest + 1, highest + 1):
        regex += "|" + str(num)
    
    return "(" + regex + ")"


def ipv4_or_ipv4_cidr_to_regex(entry: str) -> str:
    """Transforms the given IPv4 address or IPv4 CIDR block to a matching regular expression."""

    #creating a new network object and transforming its address to raw bytes
    net = ipaddress.IPv4Network(entry.strip(), strict=False)
    octets = net.network_address.packed

    parts = []
    for idx in range(4):
        #how many bits do not change in this octet (byte)
        fixed_bits_count = net.prefixlen - 8 * idx
        if fixed_bits_count > 8:
            fixed_bits_count = 8
        if fixed_bits_count < 0:
            fixed_bits_count = 0

        #all fixed -> appendins as they are; all variable -> appending the regex for the whole octet
        #otherwise -> creating the regex for the specific range
        curr_octet = octets[idx]
        if fixed_bits_count == 8:
            parts.append(str(curr_octet))
        elif fixed_bits_count == 0:
            parts.append(ANY_OCTET_REGEX)
        else:
            #computing the lowest and highest IPv4 addresses of the block
            free_bits = 8 - fixed_bits_count
            addr_count = 2 ** free_bits

            #alligning to the lowest address
            lowest_addr = (curr_octet // addr_count) * addr_count
            highest_addr = lowest_addr + addr_count - 1

            parts.append("(" + octet_range_regex(lowest_addr, highest_addr) + ")")
    return r"\.".join(parts)


def ipmatch_to_regex(argument: str) -> str | None:
    """Parses a list of IPv4 addresses or CIDR IPv4 blocks separated by commas 
       and creates a regular expression out of them"""

    #e.g. "192.168.1.0/24, 10.1.0.1"
    entries = []
    parts = argument.split(",")

    for part in parts:
        if part.strip():
            entries.append(part.strip())

    #the string is empty, no regex returned
    if not entries:
        return None  
    
    return "^(" + "|".join(ipv4_or_ipv4_cidr_to_regex(entry) for entry in entries) + ")$"
