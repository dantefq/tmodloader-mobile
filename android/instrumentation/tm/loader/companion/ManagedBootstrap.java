package tm.loader.companion;

import android.content.Context;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.io.FileInputStream;
import org.json.JSONObject;

/** Own opt-in managed demo, not arbitrary DLL execution or tModLoader compatibility. */
final class ManagedBootstrap {
    final File flag;
    final boolean available;
    boolean enabled;
    String mode="own-csharp";
    boolean cryptoRequired;
    ManagedBootstrap(Context target, Context own, boolean requested) throws Exception {
        File parent = new File(target.getFilesDir(), "tmloader");
        if (!parent.isDirectory() && !parent.mkdirs()) throw new Exception("Cannot create loader directory");
        flag = new File(parent, "managed-enabled.json");
        for (String name:new String[]{"content-command.json","content-command.json.tmp","sleep-command.json","sleep-command.json.tmp","respawn-command.json","respawn-command.json.tmp"}) {
            File prior=new File(parent,name);
            if(prior.exists() && !prior.delete()) throw new Exception("Cannot clear stale own test command");
        }
        available = requested;
        enabled = requested;
        if (requested) {
            String[] names = own.getAssets().list("managed");
            if (names == null || names.length == 0) throw new Exception("Build the managed companion before requesting C# demo");
            File folder = new File(parent, "managed");
            if (!folder.isDirectory() && !folder.mkdirs()) throw new Exception("Cannot create managed directory");
            tm.loader.shared.OwnTmod.clearDemoFiles(folder);
            for (String name : names) {
                if (!name.matches("[A-Za-z0-9_.-]+")) throw new Exception("Unexpected managed asset name");
                try (InputStream input = own.getAssets().open("managed/" + name);
                     FileOutputStream output = new FileOutputStream(new File(folder, name))) {
                    byte[] buffer = new byte[8192]; int count;
                    while ((count = input.read(buffer)) != -1) output.write(buffer, 0, count);
                }
            }
            mode=tm.loader.shared.OwnTmod.prepare(folder);
            File contractFile=new File(folder,"demo-contract.json");
            if(contractFile.isFile()) {
                if(contractFile.length()>4096)throw new Exception("Managed contract too large");
                byte[] bytes=new byte[(int)contractFile.length()];
                try(FileInputStream input=new FileInputStream(contractFile)) {
                    int done=0,n;while(done<bytes.length&&(n=input.read(bytes,done,bytes.length-done))>0)done+=n;
                    if(done!=bytes.length)throw new Exception("Managed contract truncated");
                }
                String revision=new JSONObject(new String(bytes,StandardCharsets.UTF_8)).optString("api_revision");
                cryptoRequired="managed-foundation-v1".equals(revision)||"managed-foundation-v2".equals(revision)||"respawn-snapshot".equals(mode);
            }
            if ("time-rate".equals(mode)) {
                File config=new File(parent,"sleep-config.json");
                if (!config.exists()) writeConfig(config,10);
            }
            if ("respawn-snapshot".equals(mode)) {
                File config=new File(parent,"respawn-config.json");
                if(!config.exists()) {
                    try(FileOutputStream out=new FileOutputStream(config)) {
                        out.write("{\"seconds\":3,\"adjust\":true}".getBytes(StandardCharsets.UTF_8));out.getFD().sync();
                    }
                }
            }
        }
        save();
    }
    void save() throws Exception {
        File temp = new File(flag.getParentFile(), "managed-enabled.json.tmp");
        try (FileOutputStream output = new FileOutputStream(temp)) {
            output.write(("{\"enabled\":" + enabled + "}").getBytes(StandardCharsets.UTF_8));
            output.getFD().sync();
        }
        if (!temp.renameTo(flag)) throw new Exception("Cannot save managed flag");
    }
    private static void writeConfig(File file,int value) throws Exception {
        File temp=new File(file.getParentFile(),file.getName()+".tmp");
        try (FileOutputStream out=new FileOutputStream(temp)) {
            out.write(("{\"multiplier\":"+value+"}").getBytes(StandardCharsets.UTF_8));out.getFD().sync();
        }
        if(!temp.renameTo(file))throw new Exception("Cannot save sleep config");
    }
    void toggleSleepMultiplier() throws Exception {
        if(!"time-rate".equals(mode))throw new Exception("Sleep mod unavailable");
        File file=new File(flag.getParentFile(),"sleep-config.json");
        byte[] bytes=new byte[(int)file.length()];
        if(bytes.length<1||bytes.length>1024)throw new Exception("Sleep config size differs");
        try(FileInputStream input=new FileInputStream(file)) {
            int done=0,n;while(done<bytes.length&&(n=input.read(bytes,done,bytes.length-done))>0)done+=n;
            if(done!=bytes.length)throw new Exception("Sleep config truncated");
        }
        int current=new JSONObject(new String(bytes,StandardCharsets.UTF_8)).getInt("multiplier");
        writeConfig(file,current==10?5:10);
    }
    void requestBladeTest(boolean persistent) throws Exception {
        if (!available || !enabled || !"mod-item".equals(mode)) throw new Exception("ModItem test is disabled");
        File file=new File(flag.getParentFile(),"content-command.json");
        File temp=new File(flag.getParentFile(),"content-command.json.tmp");
        try (FileOutputStream out=new FileOutputStream(temp)) {
            out.write(("{\"action\":\""+(persistent?"persist-blade":"test-blade")+"\",\"nonce\":\""+UUID.randomUUID()+"\"}").getBytes(StandardCharsets.UTF_8));
            out.getFD().sync();
        }
        if (!temp.renameTo(file)) throw new Exception("Cannot request own blade test");
    }
    void requestSleepScene(boolean useBed) throws Exception {
        if(!available || !"time-rate".equals(mode))throw new Exception("Sleep lab unavailable");
        File file=new File(flag.getParentFile(),"sleep-command.json");
        File temp=new File(flag.getParentFile(),"sleep-command.json.tmp");
        try(FileOutputStream out=new FileOutputStream(temp)) {
            out.write(("{\"action\":\""+(useBed?"use-bed":"prepare-room")+"\",\"nonce\":\""+UUID.randomUUID()+"\"}").getBytes(StandardCharsets.UTF_8));
            out.getFD().sync();
        }
        if(!temp.renameTo(file))throw new Exception("Cannot request sleep lab scene");
    }
}
