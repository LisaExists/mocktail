// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

// This minimal JNI ABI fixture is cross-compiled for Android AArch64 without
// Android headers or a sysroot. Its only imports are function pointers obtained
// from the JavaVM/JNIEnv tables supplied by the experimental guest bridge.

#include <stdint.h>

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
typedef int32_t (*GetVersionFunction)(struct JNIEnv_ *);
typedef void *(*FindClassFunction)(struct JNIEnv_ *, const char *);
typedef int32_t (*RegisterNativesFunction)(
    struct JNIEnv_ *, void *, const struct JNINativeMethod *, int32_t);

__attribute__((visibility("default")))
int guest_native_sum(int left, int right) {
  return left + right;
}

__attribute__((visibility("default")))
int32_t JNI_OnLoad(struct JavaVM_ *vm, void *reserved) {
  (void)reserved;
  if (vm == 0 || vm->functions == 0) return -1;

  const void *const *vm_functions =
      (const void *const *)vm->functions;
  GetEnvFunction get_env = (GetEnvFunction)vm_functions[6];
  if (get_env == 0) return -2;

  struct JNIEnv_ *env = 0;
  if (get_env(vm, (void **)&env, 0x00010006) != 0 ||
      env == 0 || env->functions == 0) {
    return -3;
  }

  const void *const *jni_functions =
      (const void *const *)env->functions;
  GetVersionFunction get_version =
      (GetVersionFunction)jni_functions[4];
  FindClassFunction find_class =
      (FindClassFunction)jni_functions[6];
  RegisterNativesFunction register_natives =
      (RegisterNativesFunction)jni_functions[215];
  if (get_version == 0 || find_class == 0 || register_natives == 0) {
    return -4;
  }
  if (get_version(env) < 0x00010006) return -5;

  void *clazz = find_class(env, "com/mocktail/Smoke");
  if (clazz == 0) return -6;

  const struct JNINativeMethod methods[] = {
      {"nativeSum", "(II)I", (void *)guest_native_sum},
  };
  if (register_natives(env, clazz, methods, 1) != 0) return -7;
  return 0x00010006;
}
