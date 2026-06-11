#!/usr/bin/env python3
"""
gen_db.py - build crafted enc.db binary payloads for testing.

Usage:
    python3 gen_db.py <variant> [output-file]

    If output-file is omitted, writes to stdout (binary).

Variants:
    calloc-nfile       nfile=0x10000001: calloc(n,16) wraps to 16 bytes on 32-bit
    calloc-nuser       nuser=0x36DB6DB7: calloc(n,28) wraps to 4 bytes on 32-bit
    huge-field         first user field length = 0xFFFFFFF0 (malloc fails -> NULL deref)
    truncated          magic + version only, no record counts
    wrong-magic        WXYZ instead of STOR
    wrong-version      version = 99
    empty              0 bytes
    valid-empty        valid enc.db with 0 users and 0 files

On-disk format (db.c, little-endian):
    magic   : 4 bytes  "STOR"
    version : uint32   = 2
    nuser   : uint32
      per user:
        name     : { uint32 len, len bytes }
        salt     : { uint32 len, len bytes }  (must be 16 bytes)
        opslimit : uint32
        memlimit : uint32
        verifier : { uint32 len, len bytes }  (must be 56 bytes = 24+16+16)
    nfile   : uint32
      per file:
        owner   : { uint32 len, len bytes }
        name    : { uint32 len, len bytes }
        content : { uint32 len, len bytes }   (0 bytes OR nonce||ciphertext)
"""

import struct
import sys

MAGIC = b"STOR"
VERSION = 2

# Argon2id INTERACTIVE defaults (matching db.c)
OPS_INTERACTIVE = 2
MEM_INTERACTIVE = 67108864  # 64 MB

# KDF_SALT_BYTES = 16, VERIFIER_LEN = 24 + 16 + 16 = 56
SALT_LEN = 16
VERIFIER_LEN = 56


def u32(v):
    return struct.pack("<I", v & 0xFFFFFFFF)


def field(data):
    if isinstance(data, str):
        data = data.encode()
    return u32(len(data)) + data


def header():
    return MAGIC + u32(VERSION)


def user_record(name, salt=None, opslimit=OPS_INTERACTIVE,
                memlimit=MEM_INTERACTIVE, verifier=None):
    if salt is None:
        salt = b"\x00" * SALT_LEN
    if verifier is None:
        verifier = b"\x00" * VERIFIER_LEN
    return (field(name) + field(salt) +
            u32(opslimit) + u32(memlimit) +
            field(verifier))


def file_record(owner, name, content=b""):
    return field(owner) + field(name) + field(content)


# ---- variants ---------------------------------------------------------------

def variant_valid_empty():
    return header() + u32(0) + u32(0)


def variant_wrong_magic():
    return b"WXYZ" + u32(VERSION) + u32(0) + u32(0)


def variant_wrong_version():
    return MAGIC + u32(99) + u32(0) + u32(0)


def variant_truncated():
    """Stops immediately after version — no nuser/nfile counts."""
    return MAGIC + u32(VERSION)


def variant_empty():
    return b""


def variant_calloc_nfile():
    """
    nfile = 0x10000001: on 32-bit, calloc(0x10000001, 16) calls
    malloc(0x10000001 * 16) = malloc(0x10) = 16 bytes allocated.
    The loop at i=1 writes File struct fields past the end of the 16-byte chunk,
    corrupting the heap.

    We include one complete file record so the loop reaches i=1.
    At i=1 the first get_field writes a NULL to db->files+16 (past allocation)
    before returning failure, corrupting the adjacent heap chunk header.
    """
    n = 0x10000001
    rec = file_record(b"x", b"x", b"")
    return header() + u32(0) + u32(n) + rec


def variant_calloc_nuser():
    """
    nuser = 0x36DB6DB7: calloc(0x36DB6DB7, 28) = malloc(4) on 32-bit.
    At i=0: db->users[0].name writes 4 bytes (one pointer) filling the 4-byte
    allocation. db->users[0].salt at offset 4 overflows immediately.

    We include one user record with valid-looking (though bogus) salt/verifier
    sizes so the loop makes it past the name assignment to the salt assignment.
    """
    n = 0x36DB6DB7
    rec = user_record(b"x")
    return header() + u32(n) + rec + u32(0)


def variant_huge_field():
    """
    First user name field length = 0xFFFFFFF0.
    Teams without a DB_MAX_FIELD cap call malloc(0xFFFFFFF0 + 1).
    On 32-bit: 0xFFFFFFF0 + 1 = 0xFFFFFFF1, malloc fails -> NULL.
    Then buf[len] = '\0' (null-terminate) dereferences NULL -> SIGSEGV.
    """
    bad_len = 0xFFFFFFF0
    n = 1
    rec = u32(bad_len) + b""   # length prefix; no payload bytes (file ends here)
    return header() + u32(n) + rec


# ---- dispatch ---------------------------------------------------------------

VARIANTS = {
    "calloc-nfile":  variant_calloc_nfile,
    "calloc-nuser":  variant_calloc_nuser,
    "huge-field":    variant_huge_field,
    "truncated":     variant_truncated,
    "wrong-magic":   variant_wrong_magic,
    "wrong-version": variant_wrong_version,
    "empty":         variant_empty,
    "valid-empty":   variant_valid_empty,
}


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in VARIANTS:
        print(f"usage: {sys.argv[0]} <variant> [output-file]", file=sys.stderr)
        print(f"variants: {', '.join(sorted(VARIANTS))}", file=sys.stderr)
        sys.exit(1)

    data = VARIANTS[sys.argv[1]]()

    if len(sys.argv) >= 3:
        with open(sys.argv[2], "wb") as f:
            f.write(data)
        print(f"wrote {len(data)} bytes to {sys.argv[2]}", file=sys.stderr)
    else:
        sys.stdout.buffer.write(data)


if __name__ == "__main__":
    main()
