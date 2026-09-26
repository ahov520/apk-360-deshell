#!/usr/bin/env python3
"""Classify dumped dexes as APP / FRAMEWORK / SHELL by DEFINED classes.

Parses class_defs (not string refs) so framework vs app is accurate. Keep APP,
drop FRAMEWORK and SHELL when reassembling.

Usage: python defined_classes.py <dex...>   (globs allowed)
"""
import struct, sys, glob, collections


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
        return None, d[:4].hex()
    sio = struct.unpack_from('<I', d, 0x3C)[0]
    tio = struct.unpack_from('<I', d, 0x44)[0]
    cds = struct.unpack_from('<I', d, 0x60)[0]
    cdo = struct.unpack_from('<I', d, 0x64)[0]

    def s_at(i):
        o = struct.unpack_from('<I', d, sio + i * 4)[0]
        _, p = uleb(d, o); e = d.index(b'\x00', p); return d[p:e]

    def t(ti):
        return s_at(struct.unpack_from('<I', d, tio + ti * 4)[0])

    return [t(struct.unpack_from('<I', d, cdo + i * 32)[0]) for i in range(cds)], 'ok'


APP = (b'Lcom/gentle/', b'Lio/flutter/', b'Landroidx/', b'Lcom/bytedance/',
       b'Lcom/bykv/', b'Lcom/qq/e/', b'Lcom/kwad/', b'Lcom/kwai/', b'Lcom/kuaishou/',
       b'Lcom/umeng/', b'Lcom/ss/android/', b'Lcom/google/android/gms/ads',
       b'Lcom/google/firebase/', b'Lcom/google/gson/', b'Lcom/google/protobuf/',
       b'Lcom/tencent/', b'Lokhttp3/', b'Lokio/')
SHELL = (b'Lcom/stub/', b'Lcom/qihoo/', b'Lcom/jg/', b'Lcom/tianyu/')
FW = (b'Ljava/', b'Ljavax/', b'Landroid/', b'Ldalvik/', b'Llibcore/', b'Lsun/',
      b'Lcom/android/', b'Lorg/apache/', b'Lorg/w3c/', b'Lorg/xml/', b'Landroid/icu/',
      b'Landroid/support/')

if __name__ == '__main__':
    paths = []
    for a in sys.argv[1:]:
        paths += glob.glob(a) or [a]
    for p in sorted(paths, key=lambda x: -__import__('os').path.getsize(x)):
        names, st = classes(p)
        if names is None:
            print('%-30s status=%s' % (p, st)); continue
        app = sum(n.startswith(APP) for n in names)
        shell = sum(n.startswith(SHELL) for n in names)
        fw = sum(n.startswith(FW) for n in names)
        other = len(names) - app - shell - fw
        top = collections.Counter(b'/'.join(n[1:].split(b'/')[:2]).decode('latin1', 'ignore') for n in names)
        verdict = 'SHELL' if (shell and not app) else ('FW' if fw > app + other else 'APP')
        print('%-34s defs=%-5d APP=%-5d FW=%-5d SHELL=%-3d other=%-5d -> %-5s | %s' % (
            p, len(names), app, fw, shell, other, verdict,
            ' '.join('%s:%d' % (k, v) for k, v in top.most_common(4))))
