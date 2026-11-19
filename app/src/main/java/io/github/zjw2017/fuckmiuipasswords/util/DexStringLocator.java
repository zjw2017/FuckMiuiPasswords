package io.github.zjw2017.fuckmiuipasswords.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * 极简 DEX 解析器：找出“方法字节码里 const-string 引用了某常量”的类，
 * 或“定义了某形态方法”的类。
 * <p>
 * 用于不写死混淆名地定位目标类（详见 README“抗混淆定位”）。
 * string_ids 每项 4 字节；指令线性扫描，结果只当候选类，调用方按方法形态二次确认。
 */
public final class DexStringLocator {

    public static Set<String> findClassesWithConstant(String apkPath, String needle) {
        Set<String> result = new LinkedHashSet<>();
        byte[] needleBytes = needle.getBytes(StandardCharsets.UTF_8);
        try (ZipFile zip = new ZipFile(apkPath)) {
            for (String n : listDexNames(zip)) {
                ZipEntry e = zip.getEntry(n);
                try (InputStream is = zip.getInputStream(e)) {
                    scanDex(readAll(is), needleBytes, result);
                }
            }
        } catch (IOException e) {
            Log.e("DexStringLocator io error", e);
        }
        return result;
    }

    /**
     * 找出“方法字节码里 const-string 引用了某常量”的方法，返回 {@code 类名#方法名}。
     * <p>
     * 比 {@link #findClassesWithConstant} 细一级：一个类里可能有多个方法碰过
     * 同一个常量（如 syncExtensionStr1 被序列化/反序列化/游标读写引用），
     * 调用方按方法形态（参数/返回值）二次确认唯一目标。
     */
    public static Set<String> findMethodsWithConstant(String apkPath, String needle) {
        Set<String> result = new LinkedHashSet<>();
        byte[] needleBytes = needle.getBytes(StandardCharsets.UTF_8);
        try (ZipFile zip = new ZipFile(apkPath)) {
            for (String n : listDexNames(zip)) {
                ZipEntry e = zip.getEntry(n);
                try (InputStream is = zip.getInputStream(e)) {
                    scanDexMethods(readAll(is), needleBytes, result);
                }
            }
        } catch (IOException e) {
            Log.e("DexStringLocator io error", e);
        }
        return result;
    }

    /**
     * 找出“定义了指定形态方法”的方法，返回 {@code 类名#方法名}。
     * 形态用 dex 类型描述符表达（如 {@code Ljava/lang/String;}、{@code [B}、{@code I}），
     * 参数位传 {@code null} 表示该位任意（通配）；
     * 只看类自己定义的 encoded method（不含外部引用），调用方用反射+探针二次确认。
     */
    public static Set<String> findMethodsWithShape(String apkPath, String returnTypeDesc, String... paramTypeDescs) {
        Set<String> result = new LinkedHashSet<>();
        try (ZipFile zip = new ZipFile(apkPath)) {
            for (String n : listDexNames(zip)) {
                ZipEntry e = zip.getEntry(n);
                try (InputStream is = zip.getInputStream(e)) {
                    scanDexShapes(readAll(is), returnTypeDesc, paramTypeDescs, result);
                }
            }
        } catch (IOException e) {
            Log.e("DexStringLocator io error", e);
        }
        return result;
    }

    private static List<String> listDexNames(ZipFile zip) {
        List<String> dexNames = new ArrayList<>();
        Enumeration<? extends ZipEntry> en = zip.entries();
        while (en.hasMoreElements()) {
            String n = en.nextElement().getName();
            if (n.equals("classes.dex") || (n.startsWith("classes") && n.endsWith(".dex"))) {
                dexNames.add(n);
            }
        }
        Collections.sort(dexNames);
        return dexNames;
    }

    // -------------------- dex 解析 --------------------

    private static void scanDex(byte[] dex, byte[] needle, Set<String> out) {
        if (dex.length < 0x70) return;
        int stringIdsSize = u4(dex, 0x38);
        int stringIdsOff  = u4(dex, 0x3C);
        int typeIdsOff    = u4(dex, 0x44);
        int classDefsSize = u4(dex, 0x60);
        int classDefsOff  = u4(dex, 0x64);

        // 1) 目标串的 string 索引集合（string_ids 每项 4 字节：u4 string_data_off）
        Set<Integer> target = new HashSet<>();
        for (int i = 0; i < stringIdsSize; i++) {
            int dataOff = u4(dex, stringIdsOff + 4 * i);
            int[] pos = {dataOff};
            readUleb(dex, pos);
            int start = pos[0];
            int end = start;
            while (end < dex.length && dex[end] != 0) end++;
            if (containsBytes(dex, start, end, needle)) target.add(i);
        }
        if (target.isEmpty()) return;

        // 2) 每个类的 code 里找引用
        for (int k = 0; k < classDefsSize; k++) {
            int base = classDefsOff + 32 * k;
            int classIdx = u4(dex, base);
            int classDataOff = u4(dex, base + 24);
            if (classDataOff == 0) continue;

            int[] pos = {classDataOff};
            int staticFields   = readUleb(dex, pos);
            int instanceFields = readUleb(dex, pos);
            int directMethods  = readUleb(dex, pos);
            int virtualMethods = readUleb(dex, pos);

            skipFields(dex, pos, staticFields + instanceFields);

            if (methodsReference(dex, pos, directMethods, target)
                    || methodsReference(dex, pos, virtualMethods, target)) {
                out.add(typeToName(dex, stringIdsOff, typeIdsOff, classIdx));
            }
        }
    }

    private static boolean methodsReference(byte[] dex, int[] pos, int count, Set<Integer> target) {
        for (int m = 0; m < count; m++) {
            readUleb(dex, pos);   // method_idx_diff
            readUleb(dex, pos);   // access_flags
            int codeOff = readUleb(dex, pos);
            if (codeOff != 0 && codeReferences(dex, codeOff, target)) return true;
        }
        return false;
    }

    /** 方法级扫描：引用了目标常量的方法，输出 "类名#方法名" */
    private static void scanDexMethods(byte[] dex, byte[] needle, Set<String> out) {
        if (dex.length < 0x70) return;
        int stringIdsSize = u4(dex, 0x38);
        int stringIdsOff  = u4(dex, 0x3C);
        int typeIdsOff    = u4(dex, 0x44);
        int methodIdsOff  = u4(dex, 0x5C);
        int classDefsSize = u4(dex, 0x60);
        int classDefsOff  = u4(dex, 0x64);

        // 1) 目标串的 string 索引集合
        Set<Integer> target = new HashSet<>();
        for (int i = 0; i < stringIdsSize; i++) {
            int dataOff = u4(dex, stringIdsOff + 4 * i);
            int[] pos = {dataOff};
            readUleb(dex, pos);
            int start = pos[0];
            int end = start;
            while (end < dex.length && dex[end] != 0) end++;
            if (containsBytes(dex, start, end, needle)) target.add(i);
        }
        if (target.isEmpty()) return;

        // 2) 每个类的 code 里找引用，并记下方法名（method_ids 每项 8 字节：u2 class, u2 proto, u4 name）
        for (int k = 0; k < classDefsSize; k++) {
            int base = classDefsOff + 32 * k;
            int classIdx = u4(dex, base);
            int classDataOff = u4(dex, base + 24);
            if (classDataOff == 0) continue;

            int[] pos = {classDataOff};
            int staticFields   = readUleb(dex, pos);
            int instanceFields = readUleb(dex, pos);
            int directMethods  = readUleb(dex, pos);
            int virtualMethods = readUleb(dex, pos);

            skipFields(dex, pos, staticFields + instanceFields);

            String clsName = typeToName(dex, stringIdsOff, typeIdsOff, classIdx);
            methodsCollect(dex, pos, directMethods, target, methodIdsOff, stringIdsOff, clsName, out);
            methodsCollect(dex, pos, virtualMethods, target, methodIdsOff, stringIdsOff, clsName, out);
        }
    }

    private static void methodsCollect(byte[] dex, int[] pos, int count, Set<Integer> target,
                                       int methodIdsOff, int stringIdsOff, String clsName, Set<String> out) {
        int running = 0;
        for (int m = 0; m < count; m++) {
            running += readUleb(dex, pos);   // method_idx_diff（累计成绝对 method_idx）
            readUleb(dex, pos);              // access_flags
            int codeOff = readUleb(dex, pos);
            if (codeOff != 0 && codeReferences(dex, codeOff, target)) {
                int nameIdx = u4(dex, methodIdsOff + 8 * running + 4);
                out.add(clsName + "#" + readMutf8(dex, stringIdsOff, nameIdx));
            }
        }
    }

    /** 形态级扫描：遍历每个类定义的方法，按 proto（返回值+参数描述符）匹配 */
    private static void scanDexShapes(byte[] dex, String retDesc, String[] paramDescs, Set<String> out) {
        if (dex.length < 0x70) return;
        int stringIdsOff  = u4(dex, 0x3C);
        int typeIdsOff    = u4(dex, 0x44);
        int protoIdsOff   = u4(dex, 0x4C);
        int methodIdsOff  = u4(dex, 0x5C);
        int classDefsSize = u4(dex, 0x60);
        int classDefsOff  = u4(dex, 0x64);

        for (int k = 0; k < classDefsSize; k++) {
            int base = classDefsOff + 32 * k;
            int classIdx = u4(dex, base);
            int classDataOff = u4(dex, base + 24);
            if (classDataOff == 0) continue;

            int[] pos = {classDataOff};
            int staticFields   = readUleb(dex, pos);
            int instanceFields = readUleb(dex, pos);
            int directMethods  = readUleb(dex, pos);
            int virtualMethods = readUleb(dex, pos);
            skipFields(dex, pos, staticFields + instanceFields);

            String clsName = typeToName(dex, stringIdsOff, typeIdsOff, classIdx);
            collectShapes(dex, pos, directMethods, methodIdsOff, stringIdsOff, typeIdsOff, protoIdsOff,
                    retDesc, paramDescs, clsName, out);
            collectShapes(dex, pos, virtualMethods, methodIdsOff, stringIdsOff, typeIdsOff, protoIdsOff,
                    retDesc, paramDescs, clsName, out);
        }
    }

    private static void collectShapes(byte[] dex, int[] pos, int count, int methodIdsOff, int stringIdsOff,
                                      int typeIdsOff, int protoIdsOff, String retDesc, String[] paramDescs,
                                      String clsName, Set<String> out) {
        int running = 0;
        for (int m = 0; m < count; m++) {
            running += readUleb(dex, pos);   // method_idx_diff（累计成绝对 method_idx）
            readUleb(dex, pos);              // access_flags
            readUleb(dex, pos);              // code_off（形态判定不需要）
            if (protoMatches(dex, methodIdsOff, running, stringIdsOff, typeIdsOff, protoIdsOff, retDesc, paramDescs)) {
                int nameIdx = u4(dex, methodIdsOff + 8 * running + 4);
                out.add(clsName + "#" + readMutf8(dex, stringIdsOff, nameIdx));
            }
        }
    }

    /** method_ids[idx] 的 proto 是否命中形态（proto_ids 每项 12 字节：u4 shorty, u4 ret, u4 params_off） */
    private static boolean protoMatches(byte[] dex, int methodIdsOff, int methodIdx, int stringIdsOff,
                                        int typeIdsOff, int protoIdsOff, String retDesc, String[] paramDescs) {
        int protoIdx = u2(dex, methodIdsOff + 8 * methodIdx + 2);
        int protoBase = protoIdsOff + 12 * protoIdx;
        if (!typeDesc(dex, stringIdsOff, typeIdsOff, u4(dex, protoBase + 4)).equals(retDesc)) return false;
        int paramsOff = u4(dex, protoBase + 8);
        int n = paramsOff != 0 ? u4(dex, paramsOff) : 0;
        if (n != paramDescs.length) return false;
        for (int i = 0; i < n; i++) {
            int tIdx = u2(dex, paramsOff + 4 + 2 * i);
            if (paramDescs[i] != null && !typeDesc(dex, stringIdsOff, typeIdsOff, tIdx).equals(paramDescs[i])) {
                return false;
            }
        }
        return true;
    }

    private static String typeDesc(byte[] dex, int stringIdsOff, int typeIdsOff, int typeIdx) {
        return readMutf8(dex, stringIdsOff, u4(dex, typeIdsOff + 4 * typeIdx));
    }

    private static void skipFields(byte[] dex, int[] pos, int count) {
        for (int i = 0; i < count; i++) {
            readUleb(dex, pos);
            readUleb(dex, pos);
        }
    }

    private static boolean codeReferences(byte[] dex, int codeOff, Set<Integer> target) {
        int insnsSize = u4(dex, codeOff + 12);
        int insnsOff = codeOff + 16;
        int limit = Math.min(insnsSize, (dex.length - insnsOff) / 2);
        for (int i = 0; i < limit; i++) {
            int op = u2(dex, insnsOff + 2 * i) & 0xFF;
            if (op == 0x1a && i + 1 < limit) {              // const-string vAA, idx@BBBB
                if (target.contains(u2(dex, insnsOff + 2 * (i + 1)))) return true;
            } else if (op == 0x1b && i + 2 < limit) {       // const-string-jumbo
                int idx = u2(dex, insnsOff + 2 * (i + 1))
                        | (u2(dex, insnsOff + 2 * (i + 2)) << 16);
                if (target.contains(idx)) return true;
            }
        }
        return false;
    }

    private static String typeToName(byte[] dex, int stringIdsOff, int typeIdsOff, int classIdx) {
        int descIdx = u4(dex, typeIdsOff + 4 * classIdx);
        String desc = readMutf8(dex, stringIdsOff, descIdx);
        if (desc != null && desc.length() > 2 && desc.charAt(0) == 'L' && desc.endsWith(";")) {
            return desc.substring(1, desc.length() - 1).replace('/', '.');
        }
        return desc;
    }

    private static String readMutf8(byte[] dex, int stringIdsOff, int idx) {
        int dataOff = u4(dex, stringIdsOff + 4 * idx);
        int[] pos = {dataOff};
        readUleb(dex, pos);
        int start = pos[0];
        int end = start;
        while (end < dex.length && dex[end] != 0) end++;
        return new String(dex, start, end - start, StandardCharsets.UTF_8);
    }

    // -------------------- 基础工具 --------------------

    private static boolean containsBytes(byte[] hay, int from, int to, byte[] needle) {
        int last = to - needle.length;
        for (int i = from; i <= last; i++) {
            int j = 0;
            while (j < needle.length && hay[i + j] == needle[j]) j++;
            if (j == needle.length) return true;
        }
        return false;
    }

    private static int readUleb(byte[] d, int[] pos) {
        int result = 0, shift = 0, b;
        do {
            b = d[pos[0]++] & 0xFF;
            result |= (b & 0x7F) << shift;
            shift += 7;
        } while ((b & 0x80) != 0 && shift < 35);
        return result;
    }

    private static int u2(byte[] d, int off) {
        return (d[off] & 0xFF) | ((d[off + 1] & 0xFF) << 8);
    }

    private static int u4(byte[] d, int off) {
        return (d[off] & 0xFF) | ((d[off + 1] & 0xFF) << 8)
                | ((d[off + 2] & 0xFF) << 16) | ((d[off + 3] & 0xFF) << 24);
    }

    private static byte[] readAll(InputStream is) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = is.read(buf)) > 0) bos.write(buf, 0, n);
        return bos.toByteArray();
    }

    private DexStringLocator() {}
}
