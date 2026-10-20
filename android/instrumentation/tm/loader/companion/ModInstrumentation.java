package tm.loader.companion;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.Application;
import android.app.Instrumentation;
import android.content.Intent;
import android.os.Bundle;
import android.os.Build;
import android.util.Log;
import android.view.Gravity;
import android.widget.Button;
import android.widget.FrameLayout;

/** Loads only our bridge; the target game's APK and integrity checks are preserved. */
public final class ModInstrumentation extends Instrumentation {
    private MobileRegistry registry;
    private boolean gadgetLoaded;
    private ManagedBootstrap managed;
    private LabProtection protection;
    private boolean nativeArm64;
    @Override public void onCreate(Bundle args) {
        super.onCreate(args);
        try {
            nativeArm64 = Build.SUPPORTED_ABIS.length > 0 && "arm64-v8a".equals(Build.SUPPORTED_ABIS[0]);
            registry = new MobileRegistry(getTargetContext(), getContext(), args == null ? null : args.getString("mobile_json"));
            managed = new ManagedBootstrap(getTargetContext(), getContext(), nativeArm64 && args != null && "true".equals(args.getString("managed_demo")));
            protection = new LabProtection(getTargetContext());
            if (!nativeArm64) Log.w("TMAL", "UNSUPPORTED_ABI: native ARM64 required; translated ARM Gadget not loaded; vanilla game only");
            Log.i("TMAL", "Instrumentation registry ready; original APK unchanged");
            start();
        } catch (Exception | UnsatisfiedLinkError ex) {
            Log.e("TMAL", "Instrumentation initialization failed", ex);
            Bundle result = new Bundle(); result.putString("error", ex.toString()); finish(Activity.RESULT_CANCELED, result);
        }
    }
    @Override public void callApplicationOnCreate(Application app) {
        Log.i("TMAL", "Calling original Application.onCreate");
        try {
            super.callApplicationOnCreate(app);
            Log.i("TMAL", "Original Application.onCreate returned");
        } catch (RuntimeException | Error ex) {
            Log.e("TMAL", "Original Application.onCreate failed", ex);
            throw ex;
        }
    }
    @Override public boolean onException(Object object, Throwable error) {
        Log.e("TMAL", "Android instrumentation observed exception", error);
        return super.onException(object, error);
    }
    @Override public void onStart() {
        Log.i("TMAL", "Instrumentation ready; authorized ADB launcher starts original activity");
    }
    @Override public void callActivityOnCreate(Activity activity, Bundle state) {
        if (nativeArm64 && !gadgetLoaded && activity.getClass().getName().equals("com.unity3d.player.UnityPlayerActivity")) {
            if (managed.available) {
                System.load(getContext().getApplicationInfo().nativeLibraryDir + "/libmonosgen-2.0.so");
                if(managed.cryptoRequired) {
                    System.load(getContext().getApplicationInfo().nativeLibraryDir + "/libSystem.Security.Cryptography.Native.Android.so");
                    Log.i("TMAL", "Managed API Android cryptography JNI initialized");
                }
                Log.i("TMAL", "Own C# demo Mono native library loaded; original IL2CPP unchanged");
            }
            System.load(getContext().getApplicationInfo().nativeLibraryDir + "/libfridagadget.so");
            gadgetLoaded = true;
            Log.i("TMAL", "Instrumentation Gadget loaded at Activity creation; original APK unchanged");
        }
        super.callActivityOnCreate(activity, state);
        if (!activity.getClass().getName().equals("com.unity3d.player.UnityPlayerActivity")) return;
        Button button = new Button(activity); button.setText(nativeArm64 ? "Mobile Mods" : "Mods unavailable"); button.setAlpha(0.8f);
        button.setOnClickListener(view -> {
            if (!nativeArm64) {
                new AlertDialog.Builder(activity).setTitle("Native ARM64 required")
                    .setMessage("Terraria can run through ARM translation, but this Gadget build cannot. Mods are disabled on this emulator. The original game APK is unchanged.")
                    .setPositiveButton("Close", null).show();
                return;
            }
            try {
                int jsonCount = registry.mods.length();
                int protectionIndex=jsonCount+(managed.available?1:0);
                String[] names = new String[protectionIndex+1]; boolean[] enabled = new boolean[names.length];
                names[protectionIndex]="Lab protection (god mode + no knockback)";enabled[protectionIndex]=protection.enabled;
                for (int i = 0; i < jsonCount; i++) { names[i] = registry.mods.getJSONObject(i).getString("name"); enabled[i] = registry.mods.getJSONObject(i).getBoolean("enabled"); }
                if (managed.available) { names[jsonCount] = "respawn-snapshot".equals(managed.mode) ? "ShorterRespawn (experimental lab bridge)" : "time-rate".equals(managed.mode) ? "Change Sleep Time (limited bridge)" : "mod-item".equals(managed.mode) ? "Own PC ModItem Demo (experimental)" : "global-item".equals(managed.mode) ? "Own PC GlobalItem Demo (limited API)" : "Own C# Sword Demo (not PC .tmod)"; enabled[jsonCount] = managed.enabled; }
                AlertDialog.Builder menu=new AlertDialog.Builder(activity).setTitle("Mobile mods — reload character after changes")
                    .setMultiChoiceItems(names, enabled, (dialog, index, checked) -> {
                        try {
                            if (index == protectionIndex) { protection.enabled=checked;protection.save(); }
                            else if (index == jsonCount) { managed.enabled = checked; managed.save(); }
                            else { registry.mods.getJSONObject(index).put("enabled", checked); registry.save(); }
                        }
                        catch (Exception ex) { Log.e("TMAL", "Registry save failed", ex); }
                    }).setPositiveButton("Close", null);
                if ("mod-item".equals(managed.mode)) menu.setNeutralButton("Test blade (45s)", (dialog, which) -> {
                    try {managed.requestBladeTest(false);}
                    catch (Exception ex) {Log.e("TMAL", "Own blade test rejected", ex);}
                });
                if ("mod-item".equals(managed.mode)) menu.setNegativeButton("Saveable blade (test)", (dialog, which) -> {
                    try {managed.requestBladeTest(true);}
                    catch (Exception ex) {Log.e("TMAL", "Own persistent blade rejected", ex);}
                });
                if ("time-rate".equals(managed.mode)) menu.setNeutralButton("Toggle sleep 5x / 10x", (dialog, which) -> {
                    try {managed.toggleSleepMultiplier();}
                    catch(Exception ex) {Log.e("TMAL","Sleep config rejected",ex);}
                });
                if ("time-rate".equals(managed.mode)) menu.setNegativeButton("Sleep lab", (dialog, which) ->
                    new AlertDialog.Builder(activity).setTitle("TMAL_Sleep in TMAL_Lab only")
                        .setNegativeButton("Prepare empty room", (labDialog, action) -> {
                            try {managed.requestSleepScene(false);}
                            catch(Exception ex){Log.e("TMAL","Sleep scene rejected",ex);}
                        }).setPositiveButton("Use lab bed", (labDialog, action) -> {
                            try {managed.requestSleepScene(true);}
                            catch(Exception ex){Log.e("TMAL","Sleep scene rejected",ex);}
                        }).setNeutralButton("Close",null).show());
                menu.show();
            } catch (Exception ex) { Log.e("TMAL", "Mod menu failed", ex); }
        });
        FrameLayout panel = new FrameLayout(activity);
        panel.addView(button, new FrameLayout.LayoutParams(-2, -2, Gravity.TOP | Gravity.RIGHT));
        activity.addContentView(panel, new FrameLayout.LayoutParams(-1, -1));
    }
}
