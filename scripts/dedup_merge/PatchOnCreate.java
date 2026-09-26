import org.jf.dexlib2.Opcodes;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.AccessFlags;
import org.jf.dexlib2.DexFileFactory;
import org.jf.dexlib2.dexbacked.DexBackedDexFile;
import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.iface.MethodImplementation;
import org.jf.dexlib2.immutable.*;
import org.jf.dexlib2.immutable.instruction.*;
import org.jf.dexlib2.immutable.reference.ImmutableMethodReference;

import java.io.File;
import java.util.*;

/**
 * Reconstruct a 360-nativized Activity onCreate as `super.onCreate(bundle)`.
 * Clears the NATIVE flag and gives it a real body so removing libjiagu does not
 * leave it unimplemented. Only valid when the method was a simple entry-point
 * onCreate (Flutter v2 embedding handles the rest). Any extra original logic is
 * not recovered.
 *
 * Usage: java -cp "<dexlib2>;<util>;<guava>;." PatchOnCreate in.dex out.dex \
 *        [Lcom/pkg/MainActivity;]
 * Requires org.jf.dexlib2 (smali 2.5.2).
 */
public class PatchOnCreate {
    public static void main(String[] args) throws Exception {
        String in = args[0], out = args[1];
        String targetClass = args.length > 2 ? args[2] : "Lcom/gentle/ppcat/MainActivity;";
        Opcodes op = Opcodes.forApi(28);
        DexBackedDexFile dex = DexFileFactory.loadDexFile(new File(in), op);

        List<ClassDef> newClasses = new ArrayList<>();
        boolean patched = false;
        for (ClassDef c : dex.getClasses()) {
            if (!c.getType().equals(targetClass)) { newClasses.add(c); continue; }
            String superType = c.getSuperclass();
            System.out.println(targetClass + " super=" + superType);
            List<Method> methods = new ArrayList<>();
            for (Method m : c.getMethods()) {
                if (m.getName().equals("onCreate")
                        && (m.getAccessFlags() & AccessFlags.NATIVE.getValue()) != 0) {
                    ImmutableMethodReference superOnCreate = new ImmutableMethodReference(
                            superType, "onCreate",
                            Collections.singletonList("Landroid/os/Bundle;"), "V");
                    List<ImmutableInstruction> insns = new ArrayList<>();
                    insns.add(new ImmutableInstruction35c(Opcode.INVOKE_SUPER, 2, 0, 1, 0, 0, 0, superOnCreate));
                    insns.add(new ImmutableInstruction10x(Opcode.RETURN_VOID));
                    MethodImplementation impl = new ImmutableMethodImplementation(2, insns, null, null);
                    int flags = m.getAccessFlags() & ~AccessFlags.NATIVE.getValue();
                    methods.add(new ImmutableMethod(m.getDefiningClass(), m.getName(),
                            m.getParameters(), m.getReturnType(), flags, m.getAnnotations(),
                            m.getHiddenApiRestrictions(), impl));
                    patched = true;
                    System.out.println("  patched onCreate -> invoke-super; flags now 0x" + Integer.toHexString(flags));
                } else {
                    methods.add(m);
                }
            }
            newClasses.add(new ImmutableClassDef(c.getType(), c.getAccessFlags(),
                    c.getSuperclass(), c.getInterfaces(), c.getSourceFile(),
                    c.getAnnotations(), c.getFields(), methods));
        }
        DexFileFactory.writeDexFile(out, new ImmutableDexFile(op, newClasses));
        System.out.println((patched ? "wrote " : "NO native onCreate found; wrote ") + out
                + " classes=" + newClasses.size());
    }
}
