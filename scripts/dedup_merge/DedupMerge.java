import org.jf.dexlib2.Opcodes;
import org.jf.dexlib2.DexFileFactory;
import org.jf.dexlib2.dexbacked.DexBackedDexFile;
import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.immutable.ImmutableDexFile;

import java.io.File;
import java.util.*;

public class DedupMerge {
    public static void main(String[] args) throws Exception {
        // args: outDir inDex1 inDex2 ...  (priority order: earlier owns duplicates)
        String outDir = args[0];
        Opcodes op = Opcodes.forApi(28);
        Set<String> claimed = new HashSet<>();
        int outIdx = 0;
        for (int i = 1; i < args.length; i++) {
            DexBackedDexFile dex = DexFileFactory.loadDexFile(new File(args[i]), op);
            List<ClassDef> own = new ArrayList<>();
            int dup = 0;
            for (ClassDef c : dex.getClasses()) {
                if (claimed.add(c.getType())) own.add(c);
                else dup++;
            }
            outIdx++;
            String name = (outIdx == 1) ? "classes.dex" : ("classes" + outIdx + ".dex");
            String outPath = outDir + File.separator + name;
            DexFileFactory.writeDexFile(outPath, new ImmutableDexFile(op, own));
            System.out.println(new File(args[i]).getName() + " -> " + name +
                    " kept=" + own.size() + " droppedDup=" + dup);
        }
        System.out.println("total unique classes=" + claimed.size() + " dexes=" + outIdx);
    }
}
