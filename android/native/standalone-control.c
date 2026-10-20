/* Diagnostic bootstrap only. No hooks, game changes, or protection changes. */
extern int __android_log_write(int priority, const char *tag, const char *text);

__attribute__((constructor)) static void tm_standalone_control(void) {
    __android_log_write(4, "TMALStandalone", "NATIVE_BOOTSTRAP_CONTROL_READY");
}
