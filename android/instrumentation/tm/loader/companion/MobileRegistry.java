package tm.loader.companion;

import android.content.Context;
import java.io.*;
import java.nio.charset.StandardCharsets;
import org.json.JSONArray;
import org.json.JSONObject;

final class MobileRegistry {
    final File file;
    final JSONArray mods;
    MobileRegistry(Context target, Context own, String incoming) throws Exception {
        file = new File(target.getFilesDir(), "tmloader/mods.json");
        if (file.isFile()) mods = new JSONArray(read(new FileInputStream(file)));
        else { mods = new JSONArray(); mods.put(new JSONObject(read(own.getAssets().open("tmloader/CopperSwordDemo.json")))); }
        if (mods.length() > 16) throw new IllegalArgumentException("Maximum 16 mods");
        for (int i = 0; i < mods.length(); i++) validate(mods.getJSONObject(i));
        if (incoming != null) {
            JSONObject mod = new JSONObject(incoming); validate(mod); int index = -1;
            for (int i = 0; i < mods.length(); i++) if (mods.getJSONObject(i).getString("id").equals(mod.getString("id"))) index = i;
            if (index < 0 && mods.length() >= 16) throw new IllegalArgumentException("Maximum 16 mods");
            if (index < 0) mods.put(mod); else mods.put(index, mod);
        }
        save();
    }
    static void validate(JSONObject mod) throws Exception {
        if (!"terraria-mobile-json-v1".equals(mod.getString("format"))) throw new IllegalArgumentException("Select a mobile JSON mod; PC .tmod is unsupported");
        if (!mod.getString("id").matches("[a-z0-9-]{1,48}")) throw new IllegalArgumentException("Invalid mod id");
        if (mod.getString("name").length() < 1 || mod.getString("name").length() > 64) throw new IllegalArgumentException("Invalid name");
        if (!(mod.get("enabled") instanceof Boolean)) throw new IllegalArgumentException("enabled must be boolean");
        JSONArray items = mod.getJSONArray("items");
        if (items.length() < 1 || items.length() > 32) throw new IllegalArgumentException("Expected 1–32 items");
        for (int i = 0; i < items.length(); i++) {
            JSONObject item = items.getJSONObject(i);
            Object type = item.get("type"), damage = item.get("damage");
            if (!(type instanceof Integer) || (Integer) type < 1 || (Integer) type > 6144) throw new IllegalArgumentException("Invalid vanilla item type");
            if (!(damage instanceof Integer) || (Integer) damage < 1 || (Integer) damage > 100) throw new IllegalArgumentException("damage must be an integer from 1 to 100");
            if (item.getString("name").length() < 1 || item.getString("name").length() > 48) throw new IllegalArgumentException("Invalid item name");
        }
    }
    static String read(InputStream source) throws Exception {
        try (InputStream input = source; ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[4096]; int n;
            while ((n = input.read(buffer)) != -1) {
                if (output.size() + n > 65536) throw new IllegalArgumentException("Registry exceeds 64 KiB");
                output.write(buffer, 0, n);
            }
            return new String(output.toByteArray(), StandardCharsets.UTF_8);
        }
    }
    void save() throws Exception {
        if (!file.getParentFile().isDirectory() && !file.getParentFile().mkdirs()) throw new IOException("Cannot create registry directory");
        byte[] bytes = mods.toString(2).getBytes(StandardCharsets.UTF_8);
        if (bytes.length > 65536) throw new IllegalArgumentException("Registry exceeds 64 KiB");
        File temp = new File(file.getParentFile(), "mods.json.tmp");
        try (FileOutputStream output = new FileOutputStream(temp)) { output.write(bytes); output.getFD().sync(); }
        if (!temp.renameTo(file)) throw new IOException("Cannot save registry");
    }
}
