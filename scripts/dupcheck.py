#!/usr/bin/env python3
"""Report duplicate class definitions across a set of dexes.

Non-zero duplicates mean a naive dex pick will break at runtime (load-order
dependent). Feed the same dexes to dedup_merge/DedupMerge.java to fix.

Usage: python dupcheck.py <dex...>   (globs allowed)
"""
import struct, sys, glob, os, collections


def uleb(d, o):
    r = s = 0
    while True:
        b = d[o]; o += 1; r |= (b & 0x7f) << s
        if not (b & 0x80):
            break
        s += 7
    return r, o


def classes(path):
    d = open(path, 'rb').read()
    if d[:3] != b'dex':
        return set()
    sio = struct.unpack_from('<I', d, 0x3C)[0]
    tio = struct.unpack_from('<I', d, 0x44)[0]
    cds = struct.unpack_from('<I', d, 0x60)[0]
    cdo = struct.unpack_from('<I', d, 0x64)[0]

    def s_at(i):
        o = struct.unpack_from('<I', d, sio + i * 4)[0]
        _, p = uleb(d, o); e = d.index(b'\x00', p); return d[p:e]

    def t(ti):
        return s_at(struct.unpack_from('<I', d, tio + ti * 4)[0])

    return set(t(struct.unpack_from('<I', d, cdo + i * 32)[0]) for i in range(cds))


if __name__ == '__main__':
    paths = []
    for a in sys.argv[1:]:
        paths += glob.glob(a) or [a]
    sets = {os.path.basename(p): classes(p) for p in paths}
    allc = collections.Counter()
    for s in sets.values():
        allc.update(s)
    dups = {c for c, n in allc.items() if n > 1}
    print('unique classes:', len(allc), 'duplicated:', len(dups))
    names = list(sets)
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            ov = len(sets[names[i]] & sets[names[j]])
            if ov:
                print('OVERLAP %s & %s: %d' % (names[i], names[j], ov))
    for c in list(dups)[:15]:
        holders = [f for f, s in sets.items() if c in s]
        print('  ', c.decode('latin1', 'ignore'), '->', holders)
