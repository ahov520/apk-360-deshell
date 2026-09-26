import org.jf.dexlib2.Opcodes;
import org.jf.dexlib2.DexFileFactory;
import org.jf.dexlib2.dexbacked.DexBackedDexFile;
import org.jf.dexlib2.iface.ClassDef;
import java.io.File;

public class ClassInfo {
    public static void main(String[] args) throws Exception {
        Opcodes op = Opcodes.forApi(28);
        String target = "Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;";
        for (int i = 0; i < args.length; i++) {
            DexBackedDexFile dex = DexFileFactory.loadDexFile(new File(args[i]), op);
            for (ClassDef c : dex.getClasses()) {
                String t = c.getType();
                if (t.equals(target)) {
                    System.out.println(new File(args[i]).getName() + " : " + t);
                    System.out.println("   access=0x" + Integer.toHexString(c.getAccessFlags()));
                    System.out.println("   superclass=" + c.getSuperclass());
                }
                // report any class whose simple name is 'cu' (default package) or ends with /cu;
                if (t.equals("Lcu;") || t.endsWith("/cu;")) {
                    System.out.println(new File(args[i]).getName() + " defines " + t +
                            " access=0x" + Integer.toHexString(c.getAccessFlags()) +
                            " super=" + c.getSuperclass());
                }
            }
        }
    }
}
