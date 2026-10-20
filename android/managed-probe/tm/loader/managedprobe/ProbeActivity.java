package tm.loader.managedprobe;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;

/** Isolated runtime probe. This app does not access Terraria or its saves. */
public final class ProbeActivity extends Activity {
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        TextView text = new TextView(this);
        text.setPadding(24, 24, 24, 24);
        text.setText("C# compatibility probe. An audited local mod may be loaded through our adapter. Results: TMAL log and managed/result.json. This app does not access Terraria or its saves.");
        setContentView(text);
        try {
            File folder = new File(getFilesDir(), "managed");
            if (!folder.isDirectory() && !folder.mkdirs()) throw new Exception("Cannot create managed folder");
            File prior = new File(folder, "result.json");
            if (prior.exists() && !prior.delete()) throw new Exception("Cannot remove stale probe result");
            tm.loader.shared.OwnTmod.clearDemoFiles(folder);
            for (String name : getAssets().list("managed")) {
                if (!name.matches("[A-Za-z0-9_.-]+")) throw new Exception("Unexpected asset name");
                try (InputStream input = getAssets().open("managed/" + name);
                     FileOutputStream output = new FileOutputStream(new File(folder, name))) {
                    byte[] buffer = new byte[8192]; int size;
                    while ((size = input.read(buffer)) != -1) output.write(buffer, 0, size);
                }
            }
            String mode=tm.loader.shared.OwnTmod.prepare(folder);
            Log.i("TMAL", "PROBE bundled mod mode="+mode);
            System.loadLibrary("monosgen-2.0");
            // System.Security.Cryptography uses JCA through a native JNI PAL.
            // Loading it through Java runs JNI_OnLoad and supplies the JavaVM;
            // Mono's later P/Invoke dlopen alone does not perform that step.
            System.loadLibrary("System.Security.Cryptography.Native.Android");
            Log.i("TMAL", "PROBE Android cryptography JNI initialized");
            Log.i("TMAL", "PROBE Native Mono loaded; starting own C# test");
            System.loadLibrary("fridagadget");
        } catch (Exception | UnsatisfiedLinkError error) {
            Log.e("TMAL", "PROBE Java initialization failed", error);
            text.setText(error.toString());
        }
    }
}
