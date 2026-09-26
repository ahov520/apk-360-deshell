import Java from 'frida-java-bridge';

function isDexMagic(p) {
    try {
        const b = new Uint8Array(p.readByteArray(4));
        return b[0] === 0x64 && b[1] === 0x65 && b[2] === 0x78 && b[3] === 0x0a;
    } catch (e) { return false; }
}

function dumpBegin(begin, seen, out) {
    const key = begin.toString();
    if (seen.has(key)) return;
    seen.add(key);
    try {
        const size = begin.add(0x20).readU32();
        if (size < 0x70 || size > 64 * 1024 * 1024) return;
        const buf = begin.readByteArray(size);
        const path = '/data/data/com.gentle.ppcat/cl_' + String(out.length).padStart(2, '0') + '_' + begin.toString(16) + '_' + size + '.dex';
        const f = new File(path, 'wb');
        f.write(buf);
        f.close();
        out.push(path);
        send('[CLDUMP] ' + path);
    } catch (e) { send('[dumperr] ' + e); }
}

function dumpFromLoader(loader, seen, out) {
    try {
        const BaseDexClassLoader = Java.use('dalvik.system.BaseDexClassLoader');
        const DexPathList = Java.use('dalvik.system.DexPathList');
        const Element = Java.use('dalvik.system.DexPathList$Element');
        const DexFile = Java.use('dalvik.system.DexFile');
        const Arrays = Java.use('java.util.Arrays');
        const ArrayRefl = Java.use('java.lang.reflect.Array');
        const longArr = Java.use('[J');

        const bdcl = Java.cast(loader, BaseDexClassLoader);
        const plF = BaseDexClassLoader.class.getDeclaredField('pathList'); plF.setAccessible(true);
        const pathList = plF.get(bdcl);
        if (pathList === null) return;
        const deF = DexPathList.class.getDeclaredField('dexElements'); deF.setAccessible(true);
        const elements = deF.get(pathList);
        const n = ArrayRefl.getLength(elements);
        send('[loader] ' + loader.toString() + ' elements=' + n);
        const dfF = Element.class.getDeclaredField('dexFile'); dfF.setAccessible(true);
        const ckF = DexFile.class.getDeclaredField('mCookie'); ckF.setAccessible(true);

        for (let i = 0; i < n; i++) {
            const el = ArrayRefl.get(elements, i);
            const df = dfF.get(el);
            if (df === null) continue;
            const cookie = ckF.get(df);
            if (cookie === null) continue;
            const s = Arrays.toString.overload('[J').call(Arrays, Java.cast(cookie, longArr));
            const nums = s.replace('[', '').replace(']', '').split(',');
            for (let k = 0; k < nums.length; k++) {
                const v = nums[k].trim();
                if (!v || v === '0') continue;
                let p;
                try { p = ptr(v); } catch (e) { continue; }
                if (p.isNull()) continue;
                for (let off = 0; off <= 0x48; off += 8) {
                    try {
                        const cand = p.add(off).readPointer();
                        if (isDexMagic(cand)) { dumpBegin(cand, seen, out); break; }
                    } catch (e) { }
                }
            }
        }
    } catch (e) { send('[loadererr] ' + e); }
}

function dumpAll() {
    const seen = new Set();
    const out = [];
    Java.enumerateClassLoaders({
        onMatch: function (loader) {
            try {
                const cn = loader.getClass().getName();
                if (cn && cn.indexOf('BootClassLoader') >= 0) return;
                dumpFromLoader(loader, seen, out);
            } catch (e) { }
        },
        onComplete: function () { }
    });
    return out;
}

rpc.exports = {
    dumpnow: function () {
        let res = [];
        try { Java.perform(function () { res = dumpAll(); }); }
        catch (e) { send('[rpcerr] ' + e); }
        return res;
    }
};

send('[*] agent_nohook ready');
