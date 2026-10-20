package tm.loader.texturecompanion;

import android.app.Activity;
import android.app.Instrumentation;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;

/** Separate fixed texture lab. Initialize Mono before launching Unity. */
public final class TextureInstrumentation extends Instrumentation {
    private File ready;
    @Override public void onCreate(Bundle arguments) {
        super.onCreate(arguments);
        try {
            if (Build.SUPPORTED_ABIS.length == 0 || !"arm64-v8a".equals(Build.SUPPORTED_ABIS[0]))
                throw new Exception("Native ARM64 required");
            File parent = new File(getTargetContext().getFilesDir(), "tmloader-texture-lab");
            File folder = new File(parent, "managed");
            if (!folder.isDirectory() && !folder.mkdirs()) throw new Exception("Cannot create own texture lab folder");
            ready = new File(parent, "runtime-ready");
            if (ready.exists() && !ready.delete()) throw new Exception("Cannot remove stale lab readiness marker");
            long total = 0;
            for (String name : getContext().getAssets().list("managed")) {
                if (!name.matches("[A-Za-z0-9_.-]+")) throw new Exception("Unexpected asset name");
                try (InputStream input = getContext().getAssets().open("managed/" + name);
                     FileOutputStream output = new FileOutputStream(new File(folder, name))) {
                    byte[] buffer = new byte[8192]; int count; long size = 0;
                    while ((count = input.read(buffer)) != -1) {
                        size += count; total += count;
                        if (size > 16 * 1024 * 1024 || total > 128 * 1024 * 1024) throw new Exception("Runtime assets exceed lab budget");
                        output.write(buffer, 0, count);
                    }
                }
            }
            String libraries = getContext().getApplicationInfo().nativeLibraryDir;
            System.load(libraries + "/libmonosgen-2.0.so");
            System.load(libraries + "/libSystem.Security.Cryptography.Native.Android.so");
            try (FileOutputStream output = new FileOutputStream(ready)) { output.write(1); }
            Log.i("TMALTexture", "TEXTURE_MONO_LIBRARIES_READY_BEFORE_ACTIVITY");
            Log.i("TMALTexture", "TEXTURE_INSTRUMENTATION_READY");
            start();
        } catch (Exception error) {
            Log.e("TMALTexture", "Texture lab setup failed", error);
            Bundle result = new Bundle(); result.putString("error", error.toString());
            finish(Activity.RESULT_CANCELED, result);
        }
    }
    @Override public void onStart() {
        Log.i("TMALTexture", "Waiting for the authorized launcher to start the game activity");
    }
}
