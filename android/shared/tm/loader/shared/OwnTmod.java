package tm.loader.shared;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import org.json.JSONObject;

/** Bounded reader for our two-entry unsigned test .tmod. No arbitrary mods. */
public final class OwnTmod {
    public static void clearDemoFiles(File folder) throws IOException {
        // Remove only our known compatibility outputs when changing demo variants.
        for (String name:new String[]{"demo-contract.json","tModLoader.dll","PcGlobalItemDemo.tmod","PcGlobalItemDemo.dll","PcGlobalItemDemo.dll.tmp","PcModItemDemo.tmod","PcModItemDemo.dll","PcModItemDemo.dll.tmp","ChangeSleepTime.dll","ShorterRespawn.dll","TerrariaHooks.dll","FNA.dll","ReLogic.dll","log4net.dll","Newtonsoft.Json.dll","Mono.Cecil.dll","MonoMod.Utils.dll","MonoMod.Backports.dll","MonoMod.ILHelpers.dll"}) {
            File file=new File(folder,name);
            if (file.exists() && !file.delete()) throw new IOException("Cannot replace own demo file");
        }
    }
    private static byte[] read(File file, int limit) throws Exception {
        if (file.length()<1 || file.length()>limit) throw new IOException("Own demo size outside bounds");
        ByteArrayOutputStream out=new ByteArrayOutputStream();
        try (InputStream in=new FileInputStream(file)) {
            byte[] buffer=new byte[8192]; int n;
            while ((n=in.read(buffer))!=-1) {
                if (out.size()+n>limit) throw new IOException("Own demo grew outside bounds");
                out.write(buffer,0,n);
            }
        }
        return out.toByteArray();
    }
    private static String digest(String algorithm,byte[] data) throws Exception {
        StringBuilder text=new StringBuilder();
        for (byte value:MessageDigest.getInstance(algorithm).digest(data))
            text.append(String.format(java.util.Locale.ROOT,"%02x",value&255));
        return text.toString();
    }
    private static final class Reader {
        final byte[] data; int pos;
        Reader(byte[] value) {data=value;}
        byte[] bytes(int count) throws IOException {
            if (count<0 || count>data.length-pos) throw new IOException("Truncated own .tmod");
            byte[] result=Arrays.copyOfRange(data,pos,pos+count);pos+=count;return result;
        }
        int integer() throws IOException {
            byte[] b=bytes(4);
            return (b[0]&255)|((b[1]&255)<<8)|((b[2]&255)<<16)|((b[3]&255)<<24);
        }
        String text() throws IOException {
            int length=0;
            for (int i=0;i<3;i++) {
                int value=bytes(1)[0]&255;length|=(value&127)<<(7*i);
                if ((value&128)==0) {
                    if (length>128) throw new IOException("Own .tmod string too long");
                    byte[] raw=bytes(length);String result=new String(raw,StandardCharsets.UTF_8);
                    if (!Arrays.equals(raw,result.getBytes(StandardCharsets.UTF_8))) throw new IOException("Invalid UTF-8");
                    return result;
                }
            }
            throw new IOException("Invalid string length");
        }
    }
    public static String prepare(File folder) throws Exception {
        File contractFile=new File(folder,"demo-contract.json");
        if (!contractFile.exists()) return "own-csharp";
        JSONObject contract=new JSONObject(new String(read(contractFile,4096),StandardCharsets.UTF_8));
        String mode=contract.getString("mode");
        if ("respawn-snapshot".equals(mode)) {
            String expected="aeaf65ac9b0699950ebbd033f42891c298f807fa07d665da67c77adf2d4b5e9a";
            if (!"ShorterRespawn".equals(contract.getString("mod")) ||
                !"1.2.1.1".equals(contract.getString("version")) || contract.getBoolean("live_game_supported") ||
                !expected.equals(contract.getString("mod_dll_sha256")) ||
                !expected.equals(digest("SHA-256",read(new File(folder,"ShorterRespawn.dll"),65536))))
                throw new IOException("Audited isolated respawn contract differs");
            return mode;
        }
        if ("time-rate".equals(mode)) {
            if (!"ChangeSleepTime".equals(contract.getString("mod")) || !"2025.3.6.1".equals(contract.getString("version")))
                throw new IOException("Only the audited local sleep mod is allowed");
            byte[] dll=read(new File(folder,"ChangeSleepTime.dll"),65536);
            if (!digest("SHA-256",dll).equals(contract.getString("mod_dll_sha256"))) throw new IOException("Audited mod DLL checksum differs");
            if ("managed-foundation-v2".equals(contract.optString("api_revision"))) {
                JSONObject item=contract.getJSONObject("item_contract");
                if (!"mod-item".equals(item.getString("mode")) ||
                    !"d7c838eaf97d17cf48f314f507a8d89292af47d6fe952cfe6522417bf8c14826".equals(item.getString("mod_dll_sha256")) ||
                    !"3170283e245da54517d960a0ee7667de00ee166b3fddd751e180c8f4797d47c8".equals(contract.getString("mod_dll_sha256")))
                    throw new IOException("Combined original DLL contract differs");
                prepareItem(folder,item,"mod-item");
            }
            return mode;
        }
        return prepareItem(folder,contract,mode);
    }
    private static String prepareItem(File folder,JSONObject contract,String mode) throws Exception {
        if (!"global-item".equals(mode) && !"mod-item".equals(mode)) throw new IOException("Unknown demo mode");
        String identity="mod-item".equals(mode) ? "PcModItemDemo" : "PcGlobalItemDemo";
        byte[] container=read(new File(folder,identity+".tmod"),1048576);
        if (!digest("SHA-256",container).equals(contract.getString("tmod_sha256"))) throw new IOException("Own .tmod checksum differs");
        Reader header=new Reader(container);
        if (!Arrays.equals(header.bytes(4),new byte[]{84,77,79,68}) || !"2026.8.3.0".equals(header.text())) throw new IOException("Own .tmod header differs");
        byte[] hash=header.bytes(20);
        if (!Arrays.equals(header.bytes(256),new byte[256])) throw new IOException("Unexpected own demo signature");
        int count=header.integer();byte[] payload=header.bytes(count);
        if (header.pos!=container.length || !Arrays.equals(hash,MessageDigest.getInstance("SHA-1").digest(payload))) throw new IOException("Own .tmod payload differs");
        Reader r=new Reader(payload);
        if (!identity.equals(r.text()) || !"1.0.0".equals(r.text()) || r.integer()!=2) throw new IOException("Own mod identity differs");
        String[] expected={"Info",identity+".dll"};int[] sizes=new int[2];
        for (int i=0;i<2;i++) {
            if (!expected[i].equals(r.text())) throw new IOException("Unsupported own entry");
            sizes[i]=r.integer();
            if (sizes[i]<1 || sizes[i]>65536 || r.integer()!=sizes[i]) throw new IOException("Only bounded uncompressed own entries supported");
        }
        Reader info=new Reader(r.bytes(sizes[0]));
        String[] tags={"version","1.0.0","buildVersion","2026.8.3.0","displayName","mod-item".equals(mode) ? "Own PC ModItem Demo" : "Own PC GlobalItem Demo",""};
        for (String tag:tags) if (!tag.equals(info.text())) throw new IOException("Own Info metadata differs");
        if (info.pos!=info.data.length) throw new IOException("Unexpected Info trailing data");
        byte[] dll=r.bytes(sizes[1]);
        if (r.pos!=payload.length || !digest("SHA-256",dll).equals(contract.getString("mod_dll_sha256"))) throw new IOException("Own mod DLL checksum differs");
        File temp=new File(folder,identity+".dll.tmp");
        try (FileOutputStream out=new FileOutputStream(temp)) {out.write(dll);out.getFD().sync();}
        if (!temp.renameTo(new File(folder,identity+".dll"))) throw new IOException("Cannot commit own mod DLL");
        return mode;
    }
}
