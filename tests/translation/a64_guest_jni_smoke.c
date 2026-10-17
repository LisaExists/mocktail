// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

// This minimal JNI ABI fixture is cross-compiled for Android AArch64 without
// Android headers or a sysroot. Its only imports are function pointers obtained
// from the JavaVM/JNIEnv tables supplied by the experimental guest bridge.

typedef int int32_t;  // AArch64 Android ABI uses a 32-bit int.

struct JavaVM_ {
  const void *functions;
};

struct JNIEnv_ {
  const void *functions;
};

struct JNINativeMethod {
  const char *name;
  const char *signature;
  void *function;
};

typedef int32_t (*GetEnvFunction)(struct JavaVM_ *, void **, int32_t);
typedef int32_t (*AttachCurrentThreadFunction)(struct JavaVM_ *, void **, void *);
typedef int32_t (*DetachCurrentThreadFunction)(struct JavaVM_ *);
typedef int32_t (*GetVersionFunction)(struct JNIEnv_ *);
typedef int32_t (*GetJavaVMFunction)(struct JNIEnv_ *, struct JavaVM_ **);
typedef void *(*FindClassFunction)(struct JNIEnv_ *, const char *);
typedef void *(*NewStringUTFFunction)(struct JNIEnv_ *, const char *);
typedef int32_t (*GetStringUTFLengthFunction)(struct JNIEnv_ *, void *);
typedef const char *(*GetStringUTFCharsFunction)(
    struct JNIEnv_ *, void *, unsigned char *);
typedef void (*ReleaseStringUTFCharsFunction)(
    struct JNIEnv_ *, void *, const char *);
typedef unsigned char (*ExceptionCheckFunction)(struct JNIEnv_ *);
typedef void (*ExceptionClearFunction)(struct JNIEnv_ *);
typedef int32_t (*SystemPropertyGetFunction)(const char *, char *);
extern int32_t __system_property_get(const char *, char *);
extern unsigned long getauxval(unsigned long type);
extern int android_get_device_api_level(void);
extern int *__errno(void);
extern int __android_log_write(int priority, const char *tag, const char *text);
extern int __android_log_buf_write(int buffer_id, int priority,
                                   const char *tag, const char *text);
extern int __android_log_is_loggable(int priority, const char *tag,
                                     int default_priority);
typedef int32_t (*RegisterNativesFunction)(
    struct JNIEnv_ *, void *, const struct JNINativeMethod *, int32_t);

// Android's loader runs DT_INIT/DT_INIT_ARRAY before invoking JNI_OnLoad.
// Make that ordering observable so the probe cannot accidentally appear to
// support JNI while skipping shared-object constructors.
static int guest_constructor_ran;

__attribute__((constructor))
static void guest_android_jni_constructor(void) {
  guest_constructor_ran = 0x4D4F434B;
}

__attribute__((visibility("default")))
int guest_native_sum(struct JNIEnv_ *env, void *clazz,
                     int left, int right) {
  if (env == 0 || clazz == 0) return -1000;
  return left + right;
}

__attribute__((visibility("default")))
int32_t JNI_OnLoad(struct JavaVM_ *vm, void *reserved) {
  if (guest_constructor_ran != 0x4D4F434B) return -25;
  (void)reserved;
  if (vm == 0 || vm->functions == 0) return -1;

  const void *const *vm_functions =
      (const void *const *)vm->functions;
  GetEnvFunction get_env = (GetEnvFunction)vm_functions[6];
  AttachCurrentThreadFunction attach_current_thread =
      (AttachCurrentThreadFunction)vm_functions[4];
  DetachCurrentThreadFunction detach_current_thread =
      (DetachCurrentThreadFunction)vm_functions[5];
  AttachCurrentThreadFunction attach_current_thread_as_daemon =
      (AttachCurrentThreadFunction)vm_functions[7];
  if (get_env == 0 || attach_current_thread == 0 ||
      detach_current_thread == 0 || attach_current_thread_as_daemon == 0) {
    return -2;
  }

  struct JNIEnv_ *env = 0;
  if (get_env(vm, (void **)&env, 0x00010006) != 0 ||
      env == 0 || env->functions == 0) {
    return -3;
  }

  const void *const *jni_functions =
      (const void *const *)env->functions;
  GetVersionFunction get_version =
      (GetVersionFunction)jni_functions[4];
  GetJavaVMFunction get_java_vm =
      (GetJavaVMFunction)jni_functions[219];
  FindClassFunction find_class =
      (FindClassFunction)jni_functions[6];
  NewStringUTFFunction new_string_utf =
      (NewStringUTFFunction)jni_functions[167];
  GetStringUTFLengthFunction get_string_utf_length =
      (GetStringUTFLengthFunction)jni_functions[168];
  GetStringUTFCharsFunction get_string_utf_chars =
      (GetStringUTFCharsFunction)jni_functions[169];
  ReleaseStringUTFCharsFunction release_string_utf_chars =
      (ReleaseStringUTFCharsFunction)jni_functions[170];
  ExceptionCheckFunction exception_check =
      (ExceptionCheckFunction)jni_functions[228];
  ExceptionClearFunction exception_clear =
      (ExceptionClearFunction)jni_functions[17];
  RegisterNativesFunction register_natives =
      (RegisterNativesFunction)jni_functions[215];
  if (get_version == 0 || get_java_vm == 0 || find_class == 0 || new_string_utf == 0 ||
      get_string_utf_length == 0 || get_string_utf_chars == 0 ||
      release_string_utf_chars == 0 || exception_check == 0 ||
      exception_clear == 0 || register_natives == 0) {
    return -4;
  }
  if (get_version(env) < 0x00010006) return -5;

  struct JavaVM_ *reported_vm = 0;
  if (get_java_vm(env, &reported_vm) != 0 || reported_vm != vm) return -30;
  struct JNIEnv_ *attached_env = 0;
  if (attach_current_thread(vm, (void **)&attached_env, 0) != 0 ||
      attached_env != env) return -31;
  if (detach_current_thread(vm) != 0) return -32;
  void *detached_env = 0;
  if (get_env(vm, &detached_env, 0x00010006) != -2 ||
      detached_env != 0) return -33;
  if (detach_current_thread(vm) != -2) return -34;
  attached_env = 0;
  if (attach_current_thread_as_daemon(vm, (void **)&attached_env, 0) != 0 ||
      attached_env != env) return -35;
  if (detach_current_thread(vm) != 0) return -36;
  attached_env = 0;
  if (attach_current_thread(vm, (void **)&attached_env, 0) != 0 ||
      attached_env != env) return -37;
  if (attach_current_thread(
          vm, (void **)(unsigned long long)0xDEADBEEF, 0) != -1) return -38;

  // Android's legacy property ABI must report the synthetic guest profile and
  // must not leak the host machine's actual properties.
  char sdk[92] = {0};
  if (__system_property_get("ro.build.version.sdk", sdk) != 2 ||
      sdk[0] != '3' || sdk[1] != '6' || sdk[2] != '\0') return -16;
  if (android_get_device_api_level() != 36) return -24;

  // The liblog bridge reads tag/message strings from guest memory, never
  // dereferences guest addresses as host pointers, and keeps log records single-line.
  if (!__android_log_is_loggable(6, "Mocktail", 5)) return -26;
  if (__android_log_is_loggable(4, "Mocktail", 5)) return -27;
  if (__android_log_write(4, "Mocktail", "JNI_OnLoad liblog smoke") <= 0) {
    return -28;
  }
  if (__android_log_buf_write(0, 6, "Mocktail",
                              "JNI_OnLoad liblog buffer smoke") <= 0) {
    return -29;
  }

  char missing_property[92] = {'x'};
  if (__system_property_get("ro.mocktail.property_missing", missing_property) != 0 ||
      missing_property[0] != '\0') return -17;

  // Minimal Android auxiliary-vector compatibility: page size, baseline AArch64
  // ISA capabilities and guest-resident platform/exec/random entries.
  if (getauxval(6UL) != 4096UL || getauxval(16UL) != 3UL ||
      getauxval(26UL) != 0UL) return -18;
  const char *platform =
      (const char *)(unsigned long long)getauxval(15UL);
  if (platform == (const char *)0 || platform[0] != 'a' ||
      platform[7] != '\0') return -19;
  const char *execfn =
      (const char *)(unsigned long long)getauxval(31UL);
  if (execfn == (const char *)0 || execfn[0] != 'm') return -20;
  const volatile unsigned char *random_bytes =
      (const volatile unsigned char *)(unsigned long long)getauxval(25UL);
  if (random_bytes == (const volatile unsigned char *)0) return -21;
  const unsigned char random_probe = random_bytes[0];
  (void)random_probe;
  if (getauxval(0xFFFFFFFFUL) != 0UL) return -22;
  int *guest_errno = __errno();
  if (guest_errno == (int *)0 || *guest_errno != 2) return -23;

  // Exercise JNI's modified-UTF string path from actual translated guest code.
  // The fixture uses ASCII so its modified-UTF and UTF-8 byte sequence match.
  // Invalid guest pointers must become JNI exceptions, never host faults.
  if (new_string_utf(env, (const char *)(unsigned long long)0xDEADBEEF) != 0 ||
      exception_check(env) != 1) return -8;
  exception_clear(env);
  if (exception_check(env) != 0) return -9;

  void *sample_string = new_string_utf(env, "mocktail-native");
  if (sample_string == 0) return -10;
  if (get_string_utf_length(env, sample_string) != 15) return -11;
  if (get_string_utf_chars(
          env, sample_string,
          (unsigned char *)(unsigned long long)0xDEADBEEF) != 0 ||
      exception_check(env) != 1) return -12;
  exception_clear(env);
  if (exception_check(env) != 0) return -13;

  unsigned char is_copy = 0;
  const char *sample_chars =
      get_string_utf_chars(env, sample_string, &is_copy);
  if (sample_chars == 0 || is_copy != 1 ||
      sample_chars[0] != 'm' || sample_chars[7] != 'l' ||
      sample_chars[14] != 'e' || sample_chars[15] != '\0') {
    return -14;
  }
  release_string_utf_chars(env, sample_string, sample_chars);
  if (exception_check(env) != 0) return -15;

  void *clazz = find_class(env, "com/mocktail/Smoke");
  if (clazz == 0) return -6;

  const struct JNINativeMethod methods[] = {
      {"nativeSum", "(II)I", (void *)guest_native_sum},
  };
  if (register_natives(env, clazz, methods, 1) != 0) return -7;
  return 0x00010006;
}
