"""Encoding the @ipMatch operator's argument as a regular expression."""

from __future__ import annotations

import ipaddress

#regex for 1 octet of IPv4 address (number 0-255)
ANY_OCTET_REGEX = "(" + "[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]" + ")"

#regex for 1 hexadec. digit of IPv6 address
ANY_HEX_DIGIT_REGEX = "[0-9a-f]"

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

def ipv6_or_ipv6_cidr_to_regex(entry: str) -> str:
    """Transforms the given IPv6 address or IPv6 CIDR block to a matching regular expression."""

    #the process is basically identical to the IPv4 processing

    #only the full form is accepted as input for now: 8 groups, each consisting of 4 lowercase hexadec. digits (e.g. 2001:0db8:0000:...).
    # TODO - extend

    net = ipaddress.IPv6Network(entry.strip(), strict=False)

    #the whole address as 32 individual, lowercase hexadec. digits
    hex_digits = net.network_address.packed.hex()

    digit_regexes = []
    for idx in range(32):
        fixed_bits_count = net.prefixlen - 4 * idx
        if fixed_bits_count > 4:
            fixed_bits_count = 4
        if fixed_bits_count < 0:
            fixed_bits_count = 0

        curr_digit = int(hex_digits[idx], 16)
        if fixed_bits_count == 4:
            digit_regexes.append(hex_digits[idx])
        elif fixed_bits_count == 0:
            digit_regexes.append(ANY_HEX_DIGIT_REGEX)
        else:
            free_bits = 4 - fixed_bits_count
            value_count = 2 ** free_bits

            #aligning to the lowest value
            lowest_value = (curr_digit // value_count) * value_count
            highest_value = lowest_value + value_count - 1

            #listing the allowed characters for each digit
            allowed_digits = ""
            for value in range(lowest_value, highest_value + 1):
                allowed_digits += format(value, "x")
            digit_regexes.append("[" + allowed_digits + "]")

    #joining everything together - adding the ':' characters
    groups = []
    for group_idx in range(8):
        #each group - 4 hexadec. digits
        start_idx = 4 * group_idx
        end_idx = start_idx + 4
        
        four_digit_regexes = digit_regexes[start_idx : end_idx]
        
        group = "".join(four_digit_regexes)
        groups.append(group)

    return ":".join(groups)

def entry_to_regex(entry: str) -> str:
    net = ipaddress.ip_network(entry.strip(), strict=False)
    
    if net.version == 4:
        return ipv4_or_ipv4_cidr_to_regex(entry)
    elif net.version == 6:
        return ipv6_or_ipv6_cidr_to_regex(entry)
    else:
        raise ValueError(f"Invalid format of the @ipMatch argument: {entry}")
    
def ipmatch_to_regex(argument: str) -> str | None:
    """Parses a list of IPv4/IPv6 addresses or CIDR IPv4/IPv6 blocks separated by commas 
       and creates a regular expression out of them"""

    #e.g. "192.168.1.0/24, 10.1.0.1, 2001:0db0:0000:0000:0000:0000:0000:0000/32"
    entries = []
    parts = argument.split(",")

    for part in parts:
        if part.strip():
            entries.append(part.strip())

    #the string is empty, no regex returned
    if not entries:
        return None  

    return "^(" + "|".join(entry_to_regex(entry) for entry in entries) + ")$"