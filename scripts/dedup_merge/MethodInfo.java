import org.jf.dexlib2.Opcodes;
import org.jf.dexlib2.DexFileFactory;
import org.jf.dexlib2.dexbacked.DexBackedDexFile;
import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.AccessFlags;
import java.io.File;

public class MethodInfo {
    public static void main(String[] args) throws Exception {
        Opcodes op = Opcodes.forApi(28);
        String target = args[0]; // e.g. Lcom/gentle/ppcat/MainActivity;
        int nativeCount = 0, total = 0;
        for (int i = 1; i < args.length; i++) {
            DexBackedDexFile dex = DexFileFactory.loadDexFile(new File(args[i]), op);
            for (ClassDef c : dex.getClasses()) {
                if (!c.getType().equals(target)) continue;
                System.out.println(new File(args[i]).getName() + " defines " + target +
                        " super=" + c.getSuperclass());
                for (Method m : c.getMethods()) {
                    boolean nat = (m.getAccessFlags() & AccessFlags.NATIVE.getValue()) != 0;
                    boolean hasCode = m.getImplementation() != null;
                    System.out.println("   " + m.getName() + " flags=0x" + Integer.toHexString(m.getAccessFlags()) +
                            (nat ? " NATIVE" : "") + (hasCode ? " [hasCode]" : " [noCode]"));
                }
            }
        }
    }
}
