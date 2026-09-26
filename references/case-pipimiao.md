# Seed case: com.gentle.ppcat (皮皮喵) 0.9.0 build 1143

The concrete run this skill is distilled from. Numbers are `observed`.

## Target
- Package `com.gentle.ppcat`, versionName 0.9.0, versionCode 1143, targetSdk 28,
  minSdk 19, native ABIs arm64-v8a + armeabi-v7a only (no x86).
- 360 Jiagu: manifest `application android:name="com.stub.StubApp"`;
  `assets/libjiagu.so`, `libjiagu_a64.so`, `libjiagu_x64.so`, `libjiagu_x86.so`;
  `assets/.jgapp` = `8d17c8e51b3cb2e3`.
- Flutter: `lib/arm64-v8a/libapp.so` (16.3 MB), `libflutter.so`,
  `assets/flutter_assets/`.
- Injected ad SDKs: Pangle/穿山甲 (`libpangleflipped.so`, `libsgcore.so`,
  `libzeus_direct_dex.so`, `assets/gdt_plugin/gdtadv2.jar`), Kuaishou (kwad),
  GDT (`com.qq.e`), Firebase/GMS, UMeng.
- `assets/142705263` (5.77 MB) is a ZIP = the **Pangle dynamic plugin**
  (`tt_*` resources, `PANGLEDY.RSA`, `libmaparmor.so`) — NOT the 360 payload.
- Stub `classes.dex` = 8.9 MB with only ~50 readable classes; real DEX encrypted.

## Host
Windows x86_64, no rooted phone. AVDs present: `ppm_arm64` (unbootable here),
`ppm30` (API 30 google_apis x86_64, ndk-translation, used).

## What worked (final route)
1. Boot `ppm30`, `adb root`, push `frida-server-17.18.0-android-x86_64`.
2. `adb install orig.apk` (original signature). PM chose `primaryCpuAbi=arm64-v8a`.
3. `edit_abi.sh` → `primaryCpuAbi="x86_64"` in packages.xml, `adb reboot`. Stuck
   across reboot. Process now x86_64 native → `libjiagu_x64.so` decrypts, no
   anti-tamper (original signature). Reached Flutter, died on missing x86
   libflutter (expected).
4. `frida-dexdump -U -f com.gentle.ppcat -o dump_out` → 25 dex images.
5. Classified by defined classes: 6 app dexes (sizes 6161312 / 5696084 / 6155164
   / 2508524 / 306416 / 118780), rest framework/shell. 532 duplicate classes
   across the 6.
6. DedupMerge (dexlib2) → each class once. GMS Dynamite `Lcu;` collided: three
   different `Lcu;` (measurement `super=Lab;`, ads `super=Object` final, chimera
   `super=Object`). Removed the 5 local measurement Dynamite classes → GMS device
   module used instead → `IllegalAccessError` gone.
7. `scan_native.py` → exactly ONE app native-noCode method:
   `MainActivity.onCreate`. Rebuilt it as `super.onCreate(bundle)` via
   PatchOnCreate (dexlib2).
8. apktool `-s` rebuild: manifest `android:name` restored to
   `com.gentle.ppcat.BaseApplication`, dexes swapped, `libjiagu*`/`.jgapp`
   removed, `dec/build` cleared, zipalign, debug-sign.

## Result
`dehardened6.apk`, 38,653,911 bytes, sha256
`77524ea10a3263f00b692d7f86cffe78277ff4fef2b2ac8dde37c9cc10dcb6fd`:
6 dexes, no libjiagu, no .jgapp, `application android:name=
com.gentle.ppcat.BaseApplication`. On `ppm30`:
`ActivityTaskManager: Displayed com.gentle.ppcat/.MainActivity: +1s905ms`
(and again +2s719ms), app rendered and requested runtime permissions like the
original. ~4s later Pangle `libsgcore` self-killed with `SIGILL SI_TKILL`
(`1.ui` thread, backtrace in `ndk_translation` SIMD decode) — injected ad-SDK
anti-emulator, not a de-harden defect.

## Residual limits (stated to the user)
- Debug-signed; user must re-sign with their own key.
- `MainActivity.onCreate` reconstructed as `super.onCreate` only; original extra
  logic (if any) not statically recoverable (it was DEX2C'd into libjiagu).
- Local Firebase measurement removed (uses device GMS).
- Full comic UI not reachable on the emulator due to the ad-SDK SIGILL + no real
  device; expected to run on a real arm device with a proper signature.
