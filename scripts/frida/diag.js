'use strict';

function modExp(mod, name) {
    try {
        var m = Process.findModuleByName(mod);
        if (m) { var e = m.findExportByName(name); if (e) return e; }
    } catch (e) {}
    try { if (Module.getGlobalExportByName) return Module.getGlobalExportByName(name); } catch (e) {}
    try { if (Module.findGlobalExportByName) return Module.findGlobalExportByName(name); } catch (e) {}
    return null;
}

Process.setExceptionHandler(function (details) {
    try {
        var pc = details.context.pc;
        var mod = Process.findModuleByAddress(pc);
        send('[EXC] ' + details.type + ' op=' + (details.memory ? details.memory.operation : '') +
             ' addr=' + details.address + ' pc=' + (mod ? (mod.name + '+' + pc.sub(mod.base)) : pc));
    } catch (e) { send('[EXC-ERR] ' + e); }
    return false;
});

var propHits = [];
(function () {
    var sp = modExp('libc.so', '__system_property_get');
    if (sp) {
        Interceptor.attach(sp, {
            onEnter: function (a) { try { this.k = a[0].readCString(); } catch (e) { this.k = null; } this.v = a[1]; },
            onLeave: function (r) { try { send('[prop] ' + this.k + ' = "' + this.v.readCString() + '"'); } catch (e) {} }
        });
        send('[hook] __system_property_get @' + sp);
    } else send('[miss] __system_property_get');

    ['open', 'openat', 'fopen', 'access', 'stat', 'lstat', '__openat'].forEach(function (fn) {
        var p = modExp('libc.so', fn);
        if (!p) return;
        Interceptor.attach(p, {
            onEnter: function (a) {
                try {
                    var idx = (fn === 'openat' || fn === '__openat') ? 1 : 0;
                    var path = a[idx].readCString();
                    if (path) send('[' + fn + '] ' + path);
                } catch (e) {}
            }
        });
    });
    send('[hook] file/stat opens');

    ['ptrace', 'kill', 'tgkill', 'abort', 'raise', 'exit', '_exit'].forEach(function (fn) {
        var p = modExp('libc.so', fn);
        if (p) Interceptor.attach(p, { onEnter: function (a) { send('[libc ' + fn + '] a0=' + a[0] + ' a1=' + a[1]); } });
    });

    var dl = modExp('libdl.so', 'android_dlopen_ext') || modExp('libdl.so', 'dlopen') || modExp('libc.so', 'dlopen');
    if (dl) Interceptor.attach(dl, {
        onEnter: function (a) { try { this.n = a[0].readCString(); } catch (e) { this.n = '?'; } },
        onLeave: function (r) { if (this.n) send('[dlopen] ' + this.n); }
    });
    send('[*] native hooks ready');
})();
