# Running 360's libjiagu to decrypt on an x86_64 emulator (no real device)

The whole point is to get `libjiagu` to decrypt the real DEX so it exists in
memory to dump. On a Windows/x86_64 host with no rooted phone, this is the only
path that worked.

## Why the obvious routes fail

- **arm64 AVD**: `emulator` on x86_64 Windows aborts: `Avd's CPU Architecture
  'arm64' is not supported by the QEMU2 emulator on x86_64 host. System image
  must match the host architecture.` An `arm64-v8a` AVD simply cannot boot here.
- **arm64 libjiagu under ARM→x86 translation**: if the app process runs arm64
  via ndk-translation, `libjiagu_a64.so` runs as guest ARM and crashes the
  translator: tombstone `#00 ... ndk_translation_HandleNoExec`. libjiagu uses
  self-modifying / JIT-style code the translator cannot execute.
- **Re-signing to add an x86 lib**: any re-sign trips 360 anti-tamper. libjiagu
  crashes in its own `.bss` generated code before decrypting: `Fatal signal 11
  (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x18` (or `0x28`). Confirmed by
  running an unmodified original with the SAME emulator: it does NOT crash there.

## The working setup

1. Use an **x86_64 `google_apis` image, API 30** (Android 11). Confirm it has
   ARM translation:

   ```
   adb shell getprop ro.product.cpu.abilist    # must contain arm64-v8a
   adb shell getprop ro.dalvik.vm.native.bridge # libndk_translation.so
   adb shell getprop ro.enable.native.bridge.exec # 1
   ```

2. `adb root` (google_apis images allow it; playstore images do not).

3. Push the **x86_64** frida-server (matching your frida-python version) and run
   it as root:

   ```
   adb push frida-server-<ver>-android-x86_64 /data/local/tmp/fs
   adb shell chmod 755 /data/local/tmp/fs
   adb shell "/data/local/tmp/fs -D"     # -D daemonizes; must be root
   frida-ps -U                            # sanity check
   ```

   Download via a China-friendly GitHub mirror, e.g.
   `https://ghfast.top/https://github.com/frida/frida/releases/download/<ver>/frida-server-<ver>-android-x86_64.xz`,
   then `python -c "import lzma;open('fs','wb').write(lzma.open('fs.xz').read())"`.

4. **Install the ORIGINAL, untouched apk** (original signature — do NOT re-sign):

   ```
   adb install orig.apk
   adb shell "dumpsys package <pkg> | grep primaryCpuAbi"   # will be arm64-v8a
   ```

   PM picks `arm64-v8a` because the app only ships arm libs. That would run the
   process as translated-arm and hit the `HandleNoExec` crash. So:

5. **Force the process to x86_64 by editing packages.xml** (keeps original
   signature; this is the crux):

   ```
   adb push scripts/edit_abi.sh /data/local/tmp/edit_abi.sh
   adb shell "sh /data/local/tmp/edit_abi.sh"   # sets primaryCpuAbi="x86_64"
   adb reboot
   # after boot:
   adb root
   adb shell "dumpsys package <pkg> | grep primaryCpuAbi"   # now x86_64, persists
   ```

   `edit_abi.sh` sed-edits only the `<package name="<pkg>" ...>` line in
   `/data/system/packages.xml`, changing `primaryCpuAbi="arm64-v8a"` (or
   `armeabi-v7a`) to `x86_64`. Adjust the package name inside the script.

6. **Launch and confirm decryption.** Now the process is x86_64 native, so
   `libjiagu_x64.so` runs natively and decrypts. Evidence in logcat:

   ```
   adb shell am start -n <pkg>/.MainActivity
   adb logcat -d | findstr /C:"flutter" /C:"libflutter" /C:"jiagu"
   ```

   Success looks like the app reaching `io.flutter.embedding...` /
   `FlutterJNI.loadLibrary` and finally `UnsatisfiedLinkError: dlopen failed:
   library "libflutter.so" not found` — **this is expected and fine**: there is
   no x86 `libflutter.so`, but the DEX was already decrypted before Flutter
   loaded. If instead you get `SEGV_MAPERR fault addr 0x18` you re-signed or the
   process is still arm — fix that first.

## Dumping the decrypted DEX

Simplest and anti-frida-tolerant (memory scan, no Java hooks):

```
frida-dexdump -U -f <pkg> -o dump_out
```

It spawns, lets 360 decrypt, and scans memory for `dex\n035`. It will dump the
app dexes PLUS framework/duplicate images; classify afterward
(`references/dex-reassembly.md`).

### Authoritative classloader dump (optional, cleaner ordering)

If you need the exact app dex set/order the classloader holds, use
`scripts/frida/agent_nohook.js` (enumerate `BaseDexClassLoader.pathList
.dexElements`, read each `DexFile.mCookie` long[] via `Arrays.toString`, scan the
native `DexFile*` for the `dex\n` magic, dump). It uses `frida-java-bridge`, so
bundle it first:

```
npm install frida-java-bridge esbuild
node ./node_modules/esbuild/bin/esbuild scripts/frida/agent_nohook.js --bundle \
  --format=iife --platform=neutral "--alias:buffer=./scripts/frida/buffer_shim.js" \
  --outfile=agent_bundled.js
python scripts/frida/frida_dump.py agent_bundled.js   # spawns, polls rpc.dumpnow
```

Caveats learned the hard way:
- Do this with **frida-server 17 x86_64** (frida 16 spawn was killed by anti-frida
  on the seed device; frida-dexdump on 17 was tolerated).
- Hook the dump at `Instrumentation.newApplication` **return** (dexes loaded,
  before `installContentProviders` crashes) if you switch to a hooking variant —
  but hooking may trip anti-frida; reflection-only enumeration is safer.
- 64-bit cookie pointers exceed JS number precision — read them as strings via
  `java.util.Arrays.toString(long[])` and `ptr(str)`, never `getLong`.
