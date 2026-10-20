// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

// Empty Android system-library stand-in used only at link time to create a
// DT_NEEDED entry for liblog.so in the JNI smoke fixture. The APK integration
// deliberately omits this file, so the guest runtime must resolve that
// dependency name through its platform allow-list and the registered shims.
__attribute__((visibility("hidden")))
void mocktail_android_empty_dependency_anchor(void) {}
