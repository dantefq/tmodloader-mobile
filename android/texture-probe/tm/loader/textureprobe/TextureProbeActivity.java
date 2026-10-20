package tm.loader.textureprobe;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;
import android.util.Log;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;

/** Own isolated texture-transfer probe. No game files or external storage. */
public final class TextureProbeActivity extends Activity {
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        TextView text = new TextView(this);
        text.setPadding(24, 24, 24, 24);
        text.setText("Texture transfer laboratory. Waiting for the test controller.");
        setContentView(text);
        try {
            File folder = new File(getFilesDir(), "managed");
            if (!folder.isDirectory() && !folder.mkdirs()) throw new Exception("Cannot create probe folder");
            File ready = new File(getFilesDir(), "ready");
            if (ready.exists() && !ready.delete()) throw new Exception("Cannot remove old readiness marker");
            for (String name : getAssets().list("managed")) {
                if (!name.matches("[A-Za-z0-9_.-]+")) throw new Exception("Invalid managed asset name");
                try (InputStream input = getAssets().open("managed/" + name);
                     FileOutputStream output = new FileOutputStream(new File(folder, name))) {
                    byte[] buffer = new byte[8192]; int size;
                    while ((size = input.read(buffer)) != -1) output.write(buffer, 0, size);
                }
            }
            System.loadLibrary("monosgen-2.0");
            System.loadLibrary("System.Security.Cryptography.Native.Android");
            try (FileOutputStream output = new FileOutputStream(ready)) { output.write(1); }
            text.setText("Ready for the isolated texture transfer test.");
        } catch (Exception | UnsatisfiedLinkError error) {
            Log.e("TMALTexture", "Probe initialization failed", error);
            text.setText(error.toString());
        }
    }
}
