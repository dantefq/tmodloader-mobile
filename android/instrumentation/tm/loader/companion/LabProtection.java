package tm.loader.companion;

import android.content.Context;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import org.json.JSONObject;

/** Separate user-requested protection for offline laboratory characters. */
final class LabProtection {
    private final File file;
    boolean enabled=true;
    LabProtection(Context target) throws Exception {
        file=new File(new File(target.getFilesDir(),"tmloader"),"lab-protection.json");
        if(file.exists()) {
            if(file.length()<1||file.length()>256)throw new Exception("Protection config size differs");
            byte[] bytes=new byte[(int)file.length()];
            try(FileInputStream in=new FileInputStream(file)) {
                int done=0,n;while(done<bytes.length&&(n=in.read(bytes,done,bytes.length-done))>0)done+=n;
                if(done!=bytes.length)throw new Exception("Protection config truncated");
            }
            enabled=new JSONObject(new String(bytes,StandardCharsets.UTF_8)).getBoolean("enabled");
        }else save();
    }
    void save() throws Exception {
        File temp=new File(file.getParentFile(),file.getName()+".tmp");
        try(FileOutputStream out=new FileOutputStream(temp)) {
            out.write(("{\"enabled\":"+enabled+"}").getBytes(StandardCharsets.UTF_8));out.getFD().sync();
        }
        if(!temp.renameTo(file))throw new Exception("Cannot save protection config");
    }
}
