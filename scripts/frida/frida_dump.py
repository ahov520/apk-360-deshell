import sys, time, frida

PKG = 'com.gentle.ppcat'
script_path = sys.argv[1] if len(sys.argv) > 1 else 'agent16c.js'

dev = frida.get_usb_device(timeout=10)
print('[*] device:', dev)
pid = dev.spawn([PKG])
print('[*] spawned pid', pid)
session = dev.attach(pid)
code = open(script_path, 'r', encoding='utf-8').read()
script = session.create_script(code)

def on_message(message, data):
    if message.get('type') == 'send':
        print('MSG:', message.get('payload'))
    else:
        print('ERR:', message)
script.on('message', on_message)
script.load()
print('[*] loaded, resuming')
dev.resume(pid)

# poll dumpnow repeatedly; catch the window after decryption, before crash
got = 0
for i in range(40):
    time.sleep(0.25)
    try:
        res = script.exports_sync.dumpnow()
        if res and len(res) > got:
            print('[*] dumpnow returned', len(res), 'at +%.2fs' % (i * 0.25))
            got = len(res)
            if len(res) >= 3:
                # keep polling a bit to catch late-loaded dexes
                pass
    except Exception as e:
        print('[*] dumpnow err at +%.2fs:' % (i * 0.25), e)
        break
print('[*] final dumped count:', got)
try:
    session.detach()
except Exception:
    pass
