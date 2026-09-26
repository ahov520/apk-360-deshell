# Reassembling dumped DEX into a working de-hardened APK

After `frida-dexdump` you have many dex images (app + framework + duplicates).
Turning them into a runnable APK is where most of the work is.

## 1. Classify by DEFINED classes, not string references

`scripts/defined_classes.py dump_out/*.dex` parses `class_defs` and buckets each
dex as APP / FRAMEWORK / SHELL by the classes it *defines*. Counting string
refs (e.g. `com/google` tokens) misclassifies — a framework dex references app
strings and vice versa.

- **APP** (keep): defines `Lcom/<pkg>/`, `Lio/flutter/`, `Landroidx/`,
  ad SDKs (`Lcom/bytedance/`, `Lcom/bykv/`, `Lcom/ss/android/`, `Lcom/kwad/`,
  `Lcom/qq/e/`, `Lcom/umeng/`), `Lcom/google/firebase|gms/ads|gson|protobuf`.
- **FRAMEWORK** (drop): `Ljava/`, `Landroid/`, `Lsun/`, `Ldalvik/`,
  `Lcom/android/`, `Landroid/icu/`, `Lorg/apache/`, `android/net|media|provider`.
  frida-dexdump grabs the boot classpath too.
- **SHELL** (drop): `Lcom/stub/`, `Lcom/qihoo/`, `Lcom/jg/`, and any repackager
  injection like `Lcom/tianyu/`.

## 2. De-duplicate — mandatory

Distinct dumped dexes share hundreds of classes (overlapping memory captures).
Check with `scripts/dupcheck.py`; on the seed case it was 532 duplicated classes.
`d8` refuses to merge duplicates (`Type ... is defined multiple times`).

Use `scripts/dedup_merge/DedupMerge.java` (org.jf.dexlib2 2.5.2):

```
# deps (Maven, e.g. aliyun mirror): dexlib2-2.5.2.jar, util-2.5.2.jar, guava-*.jar
CP="libs/dexlib2-2.5.2.jar;libs/util-2.5.2.jar;libs/guava-32.1.3-jre.jar"
javac -cp "$CP" scripts/dedup_merge/DedupMerge.java
# priority order: earlier dex OWNS a duplicated class, later dexes drop it
java -cp "$CP;scripts/dedup_merge" DedupMerge out_dir app1.dex app2.dex ... stub.dex
```

Each output `classesN.dex` keeps only classes not already claimed by an earlier
input. dexlib2's `writeDexFile` writes correct headers, so no checksum fixing is
needed on the output. Every class ends up defined exactly once.

If you instead keep a raw memory-dumped dex as-is, fix its header first
(`scripts/fix_dex.py in.dex out.dex`): recompute SHA-1 signature over bytes[32:]
then adler32 checksum over bytes[12:], truncating to the header `file_size`.
Otherwise ART rejects it with `Bad checksum` and a startup `ClassNotFoundException`.

## 3. GMS Dynamite `Lcu;` collision — the subtle killer

Symptom (fatal, on the `ScionFrontendApi` thread, i.e. Firebase Analytics):

```
java.lang.IllegalAccessError: Class cu extended by class
com.google.android.gms.measurement.internal.AppMeasurementDynamiteService is
inaccessible (declaration of '...AppMeasurementDynamiteService' appears in
base.apk!classes5.dex)
```

Root cause: play-services ships **independently obfuscated Dynamite modules**
(measurement, ads, chimera loader). Each has its own package-private default-
package `Lcu;` (and `La;`, `Lb;`, …). In the original app GMS loads each module
in a **separate `DelegateLastClassLoader`**, so their `Lcu;` never collide. When
you flatten every decrypted dex into one PathClassLoader multidex, ART resolves
`AppMeasurementDynamiteService`'s superclass to the WRONG `Lcu;` (e.g. the ads
module's `final` one) → `IllegalAccessError`. Diagnose with
`scripts/dedup_merge/ClassInfo.java`:

```
java -cp "$CP;scripts/dedup_merge" ClassInfo dump_out/*.dex
# shows multiple defders of Lcu; with different super/access — proof of collision
```

A single classloader **cannot** satisfy two modules that each need their own
`Lcu;`. You cannot fix this by ordering or renaming one class (the whole default-
package namespace collides).

**Fix that works:** remove the local Firebase **measurement** Dynamite classes so
`DynamiteModule.load(..., PREFER_..., measurement)` falls back to the device's
Play Services module (isolated, correct). On the seed case those were exactly 5
classes, all unique to one dumped dex:
`AppMeasurementDynamiteService`, `AppMeasurement`,
`AppMeasurement$ConditionalUserProperty`, `measurement.module.Analytics`,
`measurement.dynamite.ModuleDescriptor`. Steps:

1. Identify which post-dedup `classesN.dex` holds them (`ClassInfo.java`).
2. If that dex holds ONLY those (after dedup it often does), delete the dex.
3. **Renumber** so `classes.dex, classes2.dex, ... classesN.dex` stay
   consecutive with no gap (ART requires it).
4. Rebuild and retest. The app then loads measurement from GMS; analytics is the
   only feature affected.

The chimera loader dynamite classes (`DynamiteLoaderV2`, `DynamiteModuleApi`,
`CronetDynamiteModuleApi`) can stay; only the colliding measurement module needs
removal.

## 4. Recover 360-nativized app methods (DEX2C)

`scripts/scan_native.py dump_out/*.dex` prints app-owned (`Lcom/<pkg>/`)
`native [noCode]` methods. These have no Java body — 360 compiled them into
libjiagu. On the seed case: exactly `MainActivity.onCreate`.

Reconstruct with `scripts/dedup_merge/PatchOnCreate.java`: it loads the dex,
finds `Lcom/<pkg>/MainActivity;`, and replaces the `native onCreate(Bundle)` with
a real body `invoke-super {p0,p1}, <superclass>->onCreate(Landroid/os/Bundle;)V;
return-void`, clearing the `native` flag. Confirm with `MethodInfo.java`
(`onCreate flags=0x4 [hasCode]`). Edit the target class constant in the source if
your package/entry differs.

Limit to state: this restores launch for a Flutter v2-embedding app (FlutterActivity
does plugin registration), but any extra logic the original `onCreate` contained
(window flags, splash, intent handling) is gone and is NOT statically recoverable.
If MANY app methods are `native [noCode]`, it is full DEX2C/VMP — stop and report.

## 5. Rebuild + sign + verify

```
apktool d -s orig.apk -o dec           # -s keeps dexes raw (no smali round-trip)
# edit dec/AndroidManifest.xml: android:name="com.stub.StubApp" -> real Application
# replace dec/classes*.dex with your reassembled + patched set
# delete dec/assets/libjiagu*.so and dec/assets/.jgapp
rmdir /s /q dec\build                   # MUST clear cache or apktool reuses old dexes
apktool b dec -o out_unsigned.apk
zipalign -f -p 4 out_unsigned.apk out_aligned.apk
apksigner sign --ks debug.keystore --ks-pass pass:android \
  --ks-key-alias androiddebugkey --key-pass pass:android \
  --out dehardened.apk out_aligned.apk
```

Verify on the emulator (the de-hardened app has no libjiagu, runs via ndk-translation):

```
adb uninstall <pkg>; adb install -r dehardened.apk
adb logcat -c; adb shell am start -n <pkg>/.MainActivity
adb logcat -d | findstr /C:"Displayed" /C:"FATAL" /C:"IllegalAccess"
adb shell screencap -p /sdcard/s.png && adb pull /sdcard/s.png
```

Done = `ActivityTaskManager: Displayed <pkg>/.MainActivity` + a screenshot of the
app's real UI. If it then dies ~4s later with `SIGILL SI_TKILL` on an ad-SDK
thread (backtrace in `ndk_translation` decoding SIMD), that is the injected ad
SDK's anti-emulator self-kill under translation — not a de-harden defect; it will
not fire on a real arm device.
