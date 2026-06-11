#!/usr/bin/env python3
"""
find_win.py - extract win() address from a 32-bit ELF binary.

Usage:
    python3 find_win.py <stor-binary>

Outputs:
    - hex address
    - decimal address
    - 4-byte little-endian representation (for stack-smashing payloads)

Also outputs the offset from a supplied base address if --base is given:
    python3 find_win.py <stor-binary> --base 0x08048000
"""

import subprocess
import sys


def find_symbol(binary, symbol="win"):
    result = subprocess.run(
        ["nm", "--defined-only", binary],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"nm failed: {result.stderr.strip()}", file=sys.stderr)
        return None

    for line in result.stdout.splitlines():
        parts = line.split()
        # nm output: <addr> <type> <name>
        if len(parts) >= 3 and parts[2] == symbol:
            return int(parts[0], 16)

    return None


def main():
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <stor-binary> [--base <hex-addr>]",
              file=sys.stderr)
        sys.exit(1)

    binary = sys.argv[1]
    base = None

    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == "--base" and i + 1 < len(sys.argv):
            base = int(sys.argv[i + 1], 16)
            i += 2
        else:
            print(f"unknown argument: {sys.argv[i]}", file=sys.stderr)
            sys.exit(1)

    addr = find_symbol(binary, "win")
    if addr is None:
        print("win() not found", file=sys.stderr)
        sys.exit(1)

    le_bytes = addr.to_bytes(4, "little")

    print(f"win() address : 0x{addr:08x}  ({addr})")
    print(f"little-endian : {le_bytes.hex()}  {list(le_bytes)}")
    print(f"python payload: b'\\x{le_bytes[0]:02x}\\x{le_bytes[1]:02x}"
          f"\\x{le_bytes[2]:02x}\\x{le_bytes[3]:02x}'")

    if base is not None:
        offset = addr - base
        print(f"offset from 0x{base:08x}: 0x{offset:x}  ({offset})")

    # Also check for ASLR / PIE (relevant for 32-bit contest binary)
    result = subprocess.run(
        ["file", binary], capture_output=True, text=True
    )
    if "shared object" in result.stdout or "pie" in result.stdout.lower():
        print("\nWARNING: binary may be position-independent (PIE/ASLR) —")
        print("         win() address above is load-time, not fixed.")
    else:
        print("\nnote: non-PIE binary — win() address is fixed at link time")

    return addr


if __name__ == "__main__":
    main()
