# Failure catalogue (exact errors seen while de-hardening 360 on x86)

Each entry is a real dead-end and its resolution. Match the error text.

## Emulator / execution

- **`Avd's CPU Architecture 'arm64' is not supported by the QEMU2 emulator on
  x86_64 host. System image must match the host architecture.`**
  → arm64 AVDs cannot boot on x86 Windows. Use an x86_64 image with
  ndk-translation.

- **Tombstone `#00 pc ... libc.so (syscall) / #01 libndk_translation.so
  (ndk_translation_HandleNoExec+...)`** while running arm64 libjiagu.
  → The translator cannot execute libjiagu's self-modifying code. Do not run the
  shell as translated-arm; force the process to x86_64 native.

- **`dlopen failed: ".../.jiagu/libjiagu_64.so" is for EM_X86_64 (62) instead of
  EM_AARCH64 (183)`**
  → Process is arm64 (translated) but 360 extracted the x86_64 libjiagu (it picks
  by `Build.SUPPORTED_ABIS[0]` = x86_64 on the emulator). Force the process to
  x86_64 so lib and process match.

- **`UnsatisfiedLinkError: dlopen failed: library "libflutter.so" not found`** in
  `MainActivity.onCreate` after the process is x86_64.
  → EXPECTED and harmless for dumping: no x86 Flutter libs exist, but the DEX was
  already decrypted before this point.

## Anti-tamper / anti-frida (360)

- **Native `SIGSEGV SEGV_MAPERR fault addr 0x18` (or `0x28`) inside libjiagu
  `.bss`, before any decryption**, on a re-signed build.
  → 360 anti-tamper detected the re-sign. Never re-sign to run the shell. Use the
  packages.xml x86_64 trick on the ORIGINAL apk (original signature intact). An
  unmodified original on the same emulator does not crash here — that is the proof
  it is anti-tamper, not anti-emulator.

- **App dies immediately after a burst of `open/fopen("/proc/self/maps")` reads**
  under a frida script that installs `Interceptor` hooks.
  → 360 anti-frida. It is triggered by hooking, not by frida's presence.
  frida-dexdump (pure memory scan) is tolerated; reflection-only Java enumeration
  is usually tolerated; `Interceptor.attach/replace` on framework methods is not.

## frida-server

- **`frida.NotSupportedError: need Gadget to attach on jailed Android; ...
  gadget-android-arm64.so`**
  → You pushed the arm64 frida-server. The emulator OS is x86_64; push
  `frida-server-<ver>-android-x86_64`.

- **`spawn` throws "jailed" although `frida-ps -U` lists processes.**
  → frida-server is running but not as root. `adb root`, then restart frida-server.

- **frida 16 `spawn` is killed by 360 but frida 17 frida-dexdump is not.**
  → Version/behaviour difference on the seed device. Prefer frida 17 x86_64 for
  the dump; if you need the Java bridge, bundle `frida-java-bridge` for 17 rather
  than dropping to 16.

- **`ReferenceError: 'Java' is not defined`** in a frida 17 script.
  → frida 17 removed the built-in bridges. Bundle `frida-java-bridge` with esbuild
  (add a `buffer` shim; it is only used by mkdex which you don't call), or use
  frida 16 where `Java` is global.

- **esbuild: `Could not resolve "buffer"`** when bundling frida-java-bridge.
  → Provide `--alias:buffer=./buffer_shim.js` (a stub exporting `Buffer`).

- **`frida-compile` install fails** (`prebuild-install ... Visual Studio is not
  installed`).
  → frida-compile pulls the native `frida` npm package. Skip it; install only the
  pure-JS `frida-java-bridge` + `esbuild` and bundle manually.

## dexlib2 / frida-java-bridge cookie

- **64-bit `DexFile*` pointers corrupted** when read from the `mCookie` long[].
  → JS numbers lose precision above 2^53. Read the array via
  `java.util.Arrays.toString(long[])` and `ptr(decimalString)`, never `getLong`.

## Reassembly

- **`d8 ... Type android.support.annotation.Keep is defined multiple times`**
  → Your dex set has duplicates. d8 will not dedup. Use DedupMerge.java (dexlib2)
  which keeps each class in the first dex that defines it.

- **`IllegalAccessError: Class cu extended by AppMeasurementDynamiteService is
  inaccessible`** on `ScionFrontendApi`.
  → GMS Dynamite module `Lcu;` collision from flattening. Remove the local
  measurement module; see dex-reassembly.md §3.

- **`UnsatisfiedLinkError: No implementation found for void ...onCreate
  (Native Method)`**
  → 360 nativized (DEX2C) that method. Reconstruct with PatchOnCreate.java; see
  dex-reassembly.md §4.

- **`apktool b` output still contains the old/removed dex.**
  → apktool reuses `dec/build/`. Delete `dec/build/` before every build.

- **Startup `Failure to verify dex file ... Bad checksum` / `ClassNotFoundException`
  for an ordinary class.**
  → A raw dumped dex has a stale header. Recompute signature (SHA-1 over bytes[32:])
  THEN checksum (adler32 over bytes[12:]): `scripts/fix_dex.py`.

## Post-launch (not de-harden defects)

- **App renders, then `SIGILL SI_TKILL` ~4s later on an ad-SDK thread (e.g.
  `1.ui`), backtrace in `ndk_translation ... DecodeSimdScalarTwoRegMisc`.**
  → Injected ad SDK (e.g. Pangle `libsgcore.so`) anti-emulator self-kill under
  ARM translation. Not caused by de-hardening; will not happen on a real arm
  device. Verify there.

- **App exits after you tap "Deny" on its permission dialogs.**
  → App-level behaviour, not a crash. Pre-grant with `pm grant` and relaunch to
  reach the main UI.
