# apk-360-deshell

A Cursor Agent Skill for **statically de-hardening 360 Jiagu (Qihoo)–protected
Android APKs** into a rebuilt, runnable APK — specifically on a **Windows/x86_64
host with no rooted physical device and no working arm64 emulator**.

It captures a full, verified de-harden of a 360-hardened **Flutter** app and the
non-obvious tricks it required:

- **Run libjiagu natively on an x86_64 emulator with the original signature** by
  editing the installed package's `primaryCpuAbi` to `x86_64` in `packages.xml`
  (defeats 360 anti-tamper without re-signing; avoids the arm64-translation crash).
- Runtime DEX dump with **frida-dexdump** (scan-only, tolerated by 360 anti-frida),
  plus an optional **frida-java-bridge classloader dump** for exact ordering.
- **DEX de-duplication** with dexlib2 (frida-dexdump captures overlapping images;
  `d8` refuses duplicate types).
- Fixing the **GMS Dynamite `Lcu;` collision** (`IllegalAccessError ...
  AppMeasurementDynamiteService`) by removing the local Firebase measurement
  module so it loads from device Play Services.
- Recovering **360 selective method nativization / DEX2C** (e.g. a `native`
  `MainActivity.onCreate` with no body) by reconstructing `super.onCreate`.
- Recognising **injected ad-SDK anti-emulator self-kill** (`SIGILL` under
  ndk-translation) as an emulator artifact, not a de-harden defect.

## Use it

Point your agent at `SKILL.md`. It assumes the upstream `apk-reverse` skill's
tooling (jadx, apktool, d8, zipalign, apksigner, `dex_dump_validate.py`) is on
PATH; this skill adds the 360-specific, no-device, x86-host workflow on top.

## Layout

```
SKILL.md                      main procedure + symptom index (start here)
references/
  emulator-x86-decrypt.md     the packages.xml x86_64 trick + frida setup + dump
  dex-reassembly.md           classify, de-dup, Dynamite fix, DEX2C recovery, rebuild
  pitfalls.md                 exact-error failure catalogue
  case-pipimiao.md            the concrete seed case (com.gentle.ppcat)
scripts/
  edit_abi.sh                 force primaryCpuAbi=x86_64 in packages.xml (root)
  defined_classes.py          classify dumped dexes APP/FRAMEWORK/SHELL
  dupcheck.py                 report cross-dex duplicate classes
  scan_native.py              find app-owned native(noCode) methods (DEX2C)
  fix_dex.py                  recompute dex signature+checksum for raw dumps
  dedup_merge/                dexlib2 tools (need dexlib2/util/guava jars):
    DedupMerge.java             merge dexes, keep each class once
    PatchOnCreate.java          rebuild a nativized Activity.onCreate
    ClassInfo.java              diagnose the Lcu; Dynamite collision
    MethodInfo.java             dump a class's method flags/impl
  frida/                      classloader dump (needs frida-java-bridge + esbuild):
    agent_nohook.js, buffer_shim.js, frida_dump.py, diag.js
```

## Script dependencies

- Python 3 for the `*.py` tools (stdlib only).
- JDK 17 + smali/dexlib2 jars for `dedup_merge/*.java`:
  `dexlib2-2.5.2.jar`, `util-2.5.2.jar`, `guava-*.jar` (Maven; e.g. aliyun mirror).
- Node + `frida-java-bridge` + `esbuild` to bundle the frida agent; a matching
  **x86_64** `frida-server` and `frida` python for the device side.

## Scope and limits

- Windows/x86 host focus; the ideas transfer to any host lacking a rooted arm
  device, but commands assume the emulator + adb workflow.
- Targets 360 Jiagu whole-DEX encryption + light DEX2C. Heavy/pervasive DEX2C/VMP
  is out of scope (say so and stop).
- Output is debug-signed; re-sign with your own key. Some app features tied to the
  original signature or to a removed Dynamite module may differ.

## Legal

For interoperability, security research, and de-obfuscating software **you own or
are authorized to analyze**. Do not use to infringe copyright or bypass licensing.
MIT licensed (see `LICENSE`).
