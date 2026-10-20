package tm.loader.companion;
import android.app.Activity;
import android.os.Bundle;
import android.widget.LinearLayout;
import android.widget.TextView;
/** Android 14 requires shell authorization to start this instrumentation. */
public final class LauncherActivity extends Activity {
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(24, 24, 24, 24);
        TextView text = new TextView(this);
        text.setText("Terraria Mobile Mods — экспериментальный загрузчик\n\nМоды работают внутри Android Terraria. Root не нужен, APK игры остаётся исходным.\n\nНа Android 14 запуск требует USB/ADB с ПК. Сохраните мир и выйдите в меню, затем запустите START_MOBILE_MODS.cmd на ПК.\n\nВ игре появится Mobile Mods. После включения или отключения перезагрузите персонажа. Импорт JSON: --mod в tools/start_mobile.py на ПК.\n\nДемо: Loader Test Sword, медный короткий меч, урон 18.\n\nПК .tmod, Calamity и Thorium пока не поддерживаются. Совместима только исследованная development-signed сборка APK 1.4.5.8.6.");
        layout.addView(text);
        setContentView(layout);
    }
}
