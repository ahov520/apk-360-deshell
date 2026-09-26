---
name: apk-360-deshell
description: >-
  De-harden (unpack) 360 Jiagu / Qihoo-protected Android APKs into a rebuilt,
  runnable APK on a Windows/x86_64 host WITHOUT a rooted physical device and
  WITHOUT arm64 emulator support. Covers the packages.xml primaryCpuAbi=x86_64
  trick to run libjiagu natively under the original signature (defeating
  anti-tamper), runtime DEX dump with frida-dexdump, authoritative classloader
  dump via frida-java-bridge, DEX de-duplication, GMS Dynamite module class
  collisions (Lcu; IllegalAccessError), 360 selective method nativization
  (DEX2C) recovery, and injected ad-SDK anti-emulator crashes. Use when the
  input is a 360-hardened APK (com.stub.StubApp, assets/libjiagu*.so,
  assets/.jgapp), especially a Flutter app, that must be statically de-hardened
  and repackaged. Trigger terms: 360加固, 去壳, 脱壳, libjiagu, StubApp, jiagu,
  DEX2C, Dynamite, IllegalAccessError cu, frida-dexdump, packages.xml abi.
disable-model-invocation: true
---

# De-hardening 360 Jiagu APKs on an x86 host (no real device)

This skill is the residue of a full, successful de-harden of a 360-hardened
Flutter APK on a Windows x86_64 machine that had **no rooted phone** and whose
emulator **could not run arm64 system images**. Every rule below cost real time.

Goal: a **rebuilt, installable APK** where the 360 shell is gone, the manifest
`android:name` is the app's real `Application`, and the app **actually launches
and renders** (verified `ActivityTaskManager: Displayed ...MainActivity`), not
just "assembles".

## The one non-obvious idea that unlocks everything

360's `libjiagu` decrypts the real DEX at `StubApp.attachBaseContext`. To dump
it you must run it. On this host you cannot:
- run it on an **arm64 emulator** (Windows x86 emulator refuses arm64 images:
  *"Avd's CPU Architecture 'arm64' is not supported by the QEMU2 emulator on
  x86_64 host"*), and
- run the **arm64 libjiagu under ARM→x86 translation** (it uses self-modifying
  code; ndk_translation dies in `ndk_translation_HandleNoExec`), and
- **re-sign** the APK to add an x86 lib (360 anti-tamper crashes libjiagu before
  decryption; native `SEGV_MAPERR fault addr 0x18/0x28`).

**The unlock:** install the ORIGINAL apk (original signature, untouched) on an
**x86_64 emulator that has ndk-translation** (`ro.dalvik.vm.native.bridge=
libndk_translation.so`, ABI list contains `arm64-v8a`), then edit the installed
package's `primaryCpuAbi` to `x86_64` in `/data/system/packages.xml` and reboot.
The process then runs **x86_64 native**, so the native `libjiagu_x64.so` runs
directly (no translation), decrypts the DEX, and — because the APK was never
re-signed — **anti-tamper passes**. Flutter later fails on missing x86
`libflutter.so`, but by then the DEX is already decrypted in memory. See
`references/emulator-x86-decrypt.md`.

## Recon — confirm it is 360 and learn the layer map

Run these first. `scripts/scan_native.py` and the recon commands in
`references/workflow.md` §recon.

| Signal | Meaning |
|---|---|
| manifest `application android:name="com.stub.StubApp"` | 360 shell entry (the thing to restore) |
| `assets/libjiagu.so` + `libjiagu_a64.so` + `libjiagu_x64.so` + `libjiagu_x86.so` | 360 Jiagu native shells (arm/arm64/x86/x64) |
| `assets/.jgapp` | 360 marker |
| `classes.dex` huge (e.g. 8.9 MB) but only ~50 readable classes | it is the shell stub; the real DEX is encrypted, not in the APK plaintext |
| `lib/*/libapp.so` + `libflutter.so` + `assets/flutter_assets/` | **Flutter app** — business logic is Dart in `libapp.so` (not in DEX, not encrypted by 360) |
| `assets/<digits>` that is a ZIP with `tt_*` / `PANGLEDY.RSA` | it is the **Pangle ad plugin**, NOT the 360 payload — do not chase it |

Do not assume `assets/<number>` is the encrypted DEX. On the case that seeded
this skill it was the Pangle dynamic plugin; the real DEX was encrypted inside
the stub `classes.dex` / `libjiagu`, recoverable only at runtime.

## Environment gate (this is where the host fights you)

- **No arm64 emulator on x86 Windows.** Use an **x86_64 `google_apis` image,
  API 30+**, which ships ndk-translation. Verify: `getprop ro.product.cpu.abilist`
  includes `arm64-v8a` and `getprop ro.dalvik.vm.native.bridge` is
  `libndk_translation.so`.
- **frida-server arch must match the emulator OS = x86_64.** Pushing the arm64
  frida-server yields `need Gadget to attach on jailed Android ...
  gadget-android-arm64.so`. Use `frida-server-<ver>-android-x86_64`.
- **frida-server must run as root** (`adb root` first) or spawn fails "jailed".
- **frida 17 removed the global `Java` bridge.** For Java-level work either
  bundle `frida-java-bridge` with esbuild (`scripts/frida/` + a `buffer` shim),
  or use frida 16.x where `Java` is global. Pure memory-scan tools
  (frida-dexdump) need no bridge and are tolerated by 360's anti-frida.
- **What triggers 360 anti-frida is `Interceptor` hooking, not frida presence.**
  frida-dexdump (scan only) survives; hooking `Instrumentation.newApplication`
  gets killed. Do reflection-only enumeration if you must use Java.

## The route, end to end

Full commands: `references/workflow.md`. Summary:

1. **Recon** → confirm 360 + Flutter, list `libjiagu*`, find the real Application
   class name (grep dumped classes for `BaseApplication`/`MainActivity`, or read
   it from the manifest of any earlier de-hardened build).
2. **Boot x86_64 emulator**, `adb root`, push x86_64 frida-server.
3. **Install ORIGINAL apk**, then force x86_64: `scripts/edit_abi.sh` edits
   `packages.xml primaryCpuAbi`, then `adb reboot`. Confirm it stuck
   (`dumpsys package <pkg> | grep primaryCpuAbi`). PMS keeps the edit across the
   reboot in practice.
4. **Dump the decrypted DEX**: `frida-dexdump -U -f <pkg> -o dump_out`. It runs
   during the decrypt window. Expect it to also grab framework/duplicate dexes.
5. **Classify** dumped dexes by DEFINED classes, not string refs
   (`scripts/defined_classes.py`). Keep only app dexes (contain `com.<pkg>`,
   `io.flutter`, `androidx`, ad SDKs); drop framework (`java/`, `android/`,
   `com/android`, `android/icu`, `org/apache`) and 360 shell
   (`com/stub`, `com/qihoo`, `com/jg`, injected `com/tianyu`).
6. **Validate** each app dex with the skill's `dex_dump_validate.py` (upstream
   apk-reverse): 360 whole-DEX encryption yields low `stub%`; a high stub% or a
   `native [noCode]` on an app method means method-level protection (step 8).
7. **Reassemble without duplicates** — this is mandatory, see below.
8. **Recover any 360-nativized app method** (DEX2C) — see below.
9. **Rebuild**: `apktool d -s` the original, restore manifest `android:name`,
   swap in your dexes, delete `assets/libjiagu*.so` + `assets/.jgapp`, `apktool b`,
   `zipalign -p 4`, `apksigner sign`. **Delete `dec/build/` before every
   `apktool b`** or it silently reuses stale cached dexes.
10. **Verify on the emulator**: install, launch, require
    `Displayed ...MainActivity` in logcat and a real screenshot. The
    de-hardened app has no libjiagu, so it runs as a normal Flutter app via
    ndk-translation.

## Reassembly rules that are NOT optional

frida-dexdump captures overlapping memory images, so the naive "pick the biggest
few dexes" produces a set with hundreds of duplicate classes. That breaks the
app in subtle, load-order-dependent ways.

- **De-duplicate every class.** Feed all app dexes (priority order) to
  `scripts/dedup_merge/DedupMerge.java` (dexlib2). Each class is kept in the
  first dex that defines it; the rest drop it. `d8` will NOT do this — it errors
  `Type ... is defined multiple times`. See `references/dex-reassembly.md`.
- **Fix DEX header integrity** on any raw memory-dumped dex you keep as-is:
  recompute SHA-1 signature then adler32 checksum (`scripts/fix_dex.py`), else
  ART rejects it "Bad checksum". (dexlib2 `writeDexFile` already writes correct
  headers, so DedupMerge output needs no fixing.)
- **GMS Dynamite modules collide and cannot be flattened.** Symptom:
  `java.lang.IllegalAccessError: Class cu extended by class
  com.google.android.gms.measurement.internal.AppMeasurementDynamiteService is
  inaccessible` on the `ScionFrontendApi` thread. Cause: several independently
  obfuscated modules each define a package-private `Lcu;` (default package);
  flattened into one classloader ART resolves the wrong one. A single
  classloader CANNOT satisfy two modules that both need their own `Lcu;`.
  **Fix:** remove the local Firebase **measurement** Dynamite classes
  (`AppMeasurementDynamiteService`, `AppMeasurement`, `measurement.dynamite.
  ModuleDescriptor`, …) so `DynamiteModule` loads the module from the device's
  Play Services instead. Then renumber `classesN.dex` to stay consecutive.
  Details + how to locate them: `references/dex-reassembly.md`.

## 360 selective method nativization (DEX2C)

360 can compile a **few** app methods to native and mark them `native` in the
DEX; their bodies live in `libjiagu`, not in the DEX. Removing libjiagu leaves
them unimplemented → `UnsatisfiedLinkError: No implementation found for ...
onCreate ... (Native Method)`.

- **Measure the blast radius**: `scripts/scan_native.py` counts app-owned
  (`Lcom/<pkg>/`) `native [noCode]` methods. On the seed case it was **exactly
  one**: `MainActivity.onCreate`.
- If it is only the entry Activity's `onCreate` (common — 360 "entry
  protection"), **reconstruct** it as `super.onCreate(bundle)` with
  `scripts/dedup_merge/PatchOnCreate.java` (dexlib2 rewrites the one method,
  clears the `native` flag). For a Flutter v2-embedding app this fully restores
  launch; any extra logic that was in the original `onCreate` is lost and cannot
  be recovered statically (state that limit).
- If many app methods are nativized, this is real DEX2C/VMP and static
  de-harden will not fully work — say so and stop.

## Symptom index — match a row before your next attempt

| You observe | Do this |
|---|---|
| arm64 emulator won't boot, "System image must match the host architecture" | give up arm64 on x86 Windows; use x86_64 image with ndk-translation |
| tombstone in `ndk_translation_HandleNoExec` when running arm64 libjiagu under translation | translation can't run libjiagu's self-modifying code; force x86_64 native instead |
| after re-sign, native `SIGSEGV SEGV_MAPERR fault addr 0x18`/`0x28` before decrypt | 360 anti-tamper detected the re-sign; do NOT re-sign — use the packages.xml x86_64 trick on the original |
| `dlopen ... libjiagu_64.so is for EM_X86_64 (62) instead of EM_AARCH64` | process is arm64(translated) but 360 loaded x86 libjiagu; force process to x86_64 (packages.xml) so they match |
| `need Gadget ... gadget-android-arm64.so` | wrong frida-server arch; push the x86_64 one |
| frida `spawn` fails "jailed" though frida-ps works | frida-server not running as root; `adb root` then restart it |
| app dies right after repeated `/proc/self/maps` reads under frida | 360 anti-frida via `Interceptor` hooks; switch to scan-only (frida-dexdump) or reflection-only |
| `IllegalAccessError: Class cu extended by AppMeasurementDynamiteService ... inaccessible` | GMS Dynamite `Lcu;` collision; remove local measurement module (see reassembly rules) |
| `UnsatisfiedLinkError: No implementation found for ... onCreate (Native Method)` | 360 nativized that app method (DEX2C); reconstruct with PatchOnCreate.java |
| `apktool b` output still contains removed/old dexes | delete `dec/build/` and rebuild; it caches |
| `Bad checksum` / startup `ClassNotFoundException` for an ordinary class | fix the dumped dex header (signature then checksum): `scripts/fix_dex.py` |
| app shows UI then dies ~4s later with `SIGILL SI_TKILL` on an ad-SDK thread (e.g. `1.ui`), backtrace in `ndk_translation` decoding SIMD | injected ad SDK (Pangle `libsgcore`) anti-emulator self-kill under translation; NOT a de-harden defect; verify on a real arm device |

## What "done" means

1. The rebuilt APK exists (path + sha256), has NO `libjiagu*`/`.jgapp`, and its
   manifest `android:name` is the real `Application`.
2. It installs and `ActivityTaskManager: Displayed <pkg>/.MainActivity` appears
   in logcat, confirmed by a screenshot of the app's own UI.
3. State the residual limits plainly: debug-signed (user must re-sign with their
   key); any reconstructed `onCreate` lost its extra logic; local Firebase
   measurement removed (uses device GMS); ad-SDK anti-emulator may still fire on
   emulators but not on real arm devices.

## References and scripts

- `references/emulator-x86-decrypt.md` — the packages.xml x86_64 trick, frida
  setup, the exact decrypt evidence to look for.
- `references/dex-reassembly.md` — classify, de-dup, Dynamite collision fix,
  DEX2C method recovery, rebuild + verify.
- `references/pitfalls.md` — the full failure catalogue with the exact errors.
- `references/case-pipimiao.md` — the concrete seed case (com.gentle.ppcat).
- `scripts/` — `edit_abi.sh`, `defined_classes.py`, `dupcheck.py`,
  `scan_native.py`, `fix_dex.py`, `dedup_merge/*.java` (dexlib2 dedup, method
  patch, inspectors), `frida/*` (classloader dump agent + diag).

This skill assumes the upstream `apk-reverse` skill's tooling (jadx, apktool,
d8, zipalign, apksigner, `dex_dump_validate.py`, `dex_strings.py`) is available;
it only adds the 360-specific, no-device, x86-host workflow on top.
