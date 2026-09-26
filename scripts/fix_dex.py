#!/usr/bin/env python3
"""Fix a raw memory-dumped DEX header so ART accepts it.

Recomputes the two integrity fields, in the required order:
  1. signature = SHA-1 over bytes[32:]   (written to offset 12, 20 bytes)
  2. checksum  = adler32 over bytes[12:] (written to offset 8, 4 bytes)
Truncates to the header's file_size (offset 0x20) if that is plausible, since
frida-dexdump / classloader dumps sometimes carry trailing bytes.

Usage: python fix_dex.py in.dex out.dex
Not needed for dexlib2 writeDexFile output (already correct).
"""
import struct, zlib, hashlib, sys


def fix(data: bytes) -> bytes:
    if data[:4] != b'dex\n':
        raise SystemExit('not a dex (bad magic): %r' % data[:8])
    file_size = struct.unpack_from('<I', data, 0x20)[0]
    if 0x70 < file_size <= len(data):
        data = data[:file_size]
    b = bytearray(data)
    b[12:32] = hashlib.sha1(bytes(b[32:])).digest()
    struct.pack_into('<I', b, 8, zlib.adler32(bytes(b[12:])) & 0xffffffff)
    return bytes(b)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit('usage: python fix_dex.py in.dex out.dex')
    out = fix(open(sys.argv[1], 'rb').read())
    open(sys.argv[2], 'wb').write(out)
    print('wrote %s (%d bytes, checksum=%08x)' %
          (sys.argv[2], len(out), struct.unpack_from('<I', out, 8)[0]))
