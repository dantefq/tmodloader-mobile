package tm.loader;

import android.app.AlertDialog;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.provider.OpenableColumns;
import android.util.Log;
import android.view.Gravity;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.Toast;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/** Experimental loader for small mobile JSON mods; this is not tModLoader. */
public final class ModActivity extends com.unity3d.player.UnityPlayerActivity {
    private static final String TAG = "TMAL";
    private static final int PICK_MOD = 4601;
    private File registry;
    private JSONArray mods;

    @Override protected void onCreate(Bundle state) {
        registry = new File(getFilesDir(), "tmloader/mods.json");
        try {
            if (!registry.exists()) {
                mods = new JSONArray();
                mods.put(new JSONObject(readBounded(getAssets().open("tmloader/CopperSwordDemo.json"))));
                save();
            } else {
                mods = new JSONArray(readBounded(new FileInputStream(registry)));
            }
            for (int i = 0; i < mods.length(); i++) validate(mods.getJSONObject(i));
            System.loadLibrary("fridagadget");
            Log.i(TAG, "Gadget loaded; game hook is still being checked");
        } catch (Exception | UnsatisfiedLinkError ex) {
            Log.e(TAG, "Loader initialization failed", ex);
            mods = new JSONArray();
            Toast.makeText(this, "Mobile loader failed. See TMAL log.", Toast.LENGTH_LONG).show();
        }
        super.onCreate(state);
        Button button = new Button(this);
        button.setText("Mobile Mods");
        button.setAlpha(0.8f);
        button.setOnClickListener(view -> showMods());
        FrameLayout panel = new FrameLayout(this);
        FrameLayout.LayoutParams position = new FrameLayout.LayoutParams(
            FrameLayout.LayoutParams.WRAP_CONTENT, FrameLayout.LayoutParams.WRAP_CONTENT,
            Gravity.TOP | Gravity.RIGHT);
        panel.addView(button, position);
        addContentView(panel, new FrameLayout.LayoutParams(
            FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT));
    }

    private void showMods() {
        String[] labels = new String[mods.length()];
        boolean[] enabled = new boolean[mods.length()];
        try {
            for (int i = 0; i < mods.length(); i++) {
                labels[i] = mods.getJSONObject(i).getString("name");
                enabled[i] = mods.getJSONObject(i).getBoolean("enabled");
            }
        } catch (Exception ex) { fail(ex); return; }
        new AlertDialog.Builder(this)
            .setTitle("Mobile JSON mods — reload character after changes")
            .setMultiChoiceItems(labels, enabled, (dialog, index, checked) -> {
                try { mods.getJSONObject(index).put("enabled", checked); save(); }
                catch (Exception ex) { fail(ex); }
            })
            .setNeutralButton("Import JSON", (dialog, which) -> {
                Intent pick = new Intent(Intent.ACTION_OPEN_DOCUMENT);
                pick.addCategory(Intent.CATEGORY_OPENABLE);
                pick.setType("*/*");
                startActivityForResult(pick, PICK_MOD);
            })
            .setPositiveButton("Close", null)
            .setNegativeButton("About", (dialog, which) -> new AlertDialog.Builder(this)
                .setMessage("Experimental mobile loader. JSON item overrides only, single-player. " +
                    "PC .tmod / Calamity / Thorium require a separate tModLoader environment.")
                .setPositiveButton("OK", null).show())
            .show();
    }

    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (request != PICK_MOD || result != RESULT_OK || data == null) return;
        try {
            Uri uri = data.getData();
            if (uri == null) throw new IllegalArgumentException("No file selected");
            try (Cursor cursor = getContentResolver().query(uri, null, null, null, null)) {
                if (cursor != null && cursor.moveToFirst()) {
                    int column = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                    if (column >= 0 && cursor.getString(column).toLowerCase(java.util.Locale.ROOT).endsWith(".tmod"))
                        throw new IllegalArgumentException("PC .tmod needs tModLoader; select a mobile JSON mod");
                }
            }
            JSONObject incoming = new JSONObject(readBounded(getContentResolver().openInputStream(uri)));
            validate(incoming);
            int replace = -1;
            for (int i = 0; i < mods.length(); i++)
                if (mods.getJSONObject(i).getString("id").equals(incoming.getString("id"))) replace = i;
            if (replace >= 0) mods.put(replace, incoming);
            else {
                if (mods.length() >= 16) throw new IllegalArgumentException("Maximum 16 mobile mods");
                mods.put(incoming);
            }
            save();
            Toast.makeText(this, "Imported. Reload character to apply.", Toast.LENGTH_LONG).show();
            showMods();
        } catch (Exception ex) { fail(ex); }
    }

    private static void validate(JSONObject mod) throws Exception {
        if (!"terraria-mobile-json-v1".equals(mod.getString("format")))
            throw new IllegalArgumentException("Unsupported format; expected mobile JSON v1");
        if (!mod.getString("id").matches("[a-z0-9-]{1,48}"))
            throw new IllegalArgumentException("Invalid mod id");
        if (mod.getString("name").length() < 1 || mod.getString("name").length() > 64)
            throw new IllegalArgumentException("Mod name must be 1–64 characters");
        if (!(mod.get("enabled") instanceof Boolean)) throw new IllegalArgumentException("enabled must be boolean");
        JSONArray items = mod.getJSONArray("items");
        if (items.length() < 1 || items.length() > 32) throw new IllegalArgumentException("Expected 1–32 items");
        for (int i = 0; i < items.length(); i++) {
            JSONObject item = items.getJSONObject(i);
            Object type = item.get("type"), damage = item.get("damage");
            if (!(type instanceof Integer) || (Integer) type < 1 || (Integer) type > 6144)
                throw new IllegalArgumentException("Invalid vanilla item type");
            if (!(damage instanceof Integer) || (Integer) damage < 1 || (Integer) damage > 100)
                throw new IllegalArgumentException("damage must be an integer from 1 to 100");
            if (item.getString("name").length() < 1 || item.getString("name").length() > 48)
                throw new IllegalArgumentException("Item name must be 1–48 characters");
        }
    }

    private static String readBounded(InputStream source) throws Exception {
        if (source == null) throw new IllegalArgumentException("Cannot read selected file");
        try (InputStream input = source; ByteArrayOutputStream result = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[4096];
            int n;
            while ((n = input.read(buffer)) != -1) {
                if (result.size() + n > 65536) throw new IllegalArgumentException("File exceeds 64 KiB");
                result.write(buffer, 0, n);
            }
            return new String(result.toByteArray(), StandardCharsets.UTF_8);
        }
    }

    private void save() throws Exception {
        if (!registry.getParentFile().isDirectory() && !registry.getParentFile().mkdirs())
            throw new IllegalStateException("Cannot create loader directory");
        byte[] bytes = mods.toString(2).getBytes(StandardCharsets.UTF_8);
        if (bytes.length > 65536) throw new IllegalArgumentException("Combined registry exceeds 64 KiB");
        File temp = new File(registry.getParentFile(), "mods.json.tmp");
        try (FileOutputStream output = new FileOutputStream(temp)) {
            output.write(bytes); output.getFD().sync();
        }
        if (!temp.renameTo(registry)) throw new IllegalStateException("Cannot save mod registry");
        Log.i(TAG, "Registry saved: " + mods.length() + " mods");
    }

    private void fail(Exception ex) {
        Log.e(TAG, "Mod operation failed", ex);
        Toast.makeText(this, ex.getMessage(), Toast.LENGTH_LONG).show();
    }
}
