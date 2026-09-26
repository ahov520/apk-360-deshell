#!/usr/bin/env python3
"""Count app-owned native methods with no code (360 DEX2C nativization).

A handful (often just MainActivity.onCreate) means 360 "entry protection":
reconstruct them (see dedup_merge/PatchOnCreate.java). Many means real DEX2C/VMP:
static de-harden won't fully work.

Usage: python scan_native.py <app_pkg_prefix> <dex...>
  e.g. python scan_native.py com/gentle/ppcat dump_out/*.dex
"""
import struct, sys, glob

NATIVE = 0x100


def uleb(d, o):
    r = s = 0
    while True:
        b = d[o]; o += 1; r |= (b & 0x7f) << s
        if not (b & 0x80):
            break
        s += 7
    return r, o


def scan(path, prefix):
    d = open(path, 'rb').read()
    if d[:3] != b'dex':
        return 0, []
    sio = struct.unpack_from('<I', d, 0x3C)[0]
    tio = struct.unpack_from('<I', d, 0x44)[0]
    mio = struct.unpack_from('<I', d, 0x5C)[0]
    cds = struct.unpack_from('<I', d, 0x60)[0]
    cdo = struct.unpack_from('<I', d, 0x64)[0]

    def s_at(i):
        o = struct.unpack_from('<I', d, sio + i * 4)[0]
        _, p = uleb(d, o); e = d.index(b'\x00', p); return d[p:e]

    def t(ti):
        return s_at(struct.unpack_from('<I', d, tio + ti * 4)[0])

    def mname(mi):
        return s_at(struct.unpack_from('<I', d, mio + mi * 8 + 4)[0])

    total = 0
    app = []
    for i in range(cds):
        base = cdo + i * 32
        typ = t(struct.unpack_from('<I', d, base)[0])
        cdoff = struct.unpack_from('<I', d, base + 24)[0]
        if cdoff == 0:
            continue
        o = cdoff
        sf, o = uleb(d, o); inf, o = uleb(d, o); dm, o = uleb(d, o); vm, o = uleb(d, o)
        for _ in range(sf + inf):
            _, o = uleb(d, o); _, o = uleb(d, o)
        for group in (dm, vm):
            midx = 0
            for _ in range(group):
                diff, o = uleb(d, o); af, o = uleb(d, o); code, o = uleb(d, o)
                midx += diff
                if af & NATIVE:
                    total += 1
                    if typ.startswith(b'L' + prefix):
                        app.append('%s->%s %s' % (typ.decode('latin1'),
                                   mname(midx).decode('latin1'),
                                   '[noCode]' if code == 0 else '[code!]'))
    return total, app


if __name__ == '__main__':
    if len(sys.argv) < 3:
        raise SystemExit('usage: python scan_native.py <pkg/prefix> <dex...>')
    prefix = sys.argv[1].encode()
    paths = []
    for a in sys.argv[2:]:
        paths += glob.glob(a) or [a]
    grand = 0
    for p in sorted(paths):
        tot, app = scan(p, prefix)
        print('%s total_native=%d app_native=%d' % (p, tot, len(app)))
        for x in app:
            print('   ', x)
        grand += len(app)
    print('GRAND app-owned native methods:', grand)
