// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

// This fixture builds for Android AArch64 without an NDK sysroot. These
// imports are resolved by Mocktail guest-side libdl thunks; no host pointer
// or host dlopen/dlsym API is exposed to the guest process.
__attribute__((visibility("default")))
extern void *dlopen(const char *filename, int flags);
__attribute__((visibility("default")))
extern void *dlsym(void *handle, const char *symbol);
__attribute__((visibility("default")))
extern int dlclose(void *handle);
__attribute__((visibility("default")))
extern char *dlerror(void);
struct DlInfo {
  const char *dli_fname;
  void *dli_fbase;
  const char *dli_sname;
  void *dli_saddr;
};
extern int dladdr(const void *address, struct DlInfo *info);

typedef int (*guest_dl_target_fn)(int);

__attribute__((visibility("default")))
int guest_dl_target(int value) {
  return value + 1;
}

__attribute__((visibility("default")))
int guest_dlopen_smoke(void) {
  void *handle = dlopen("libmocktail-android-dl-smoke.so", 2 /* RTLD_NOW */);
  if (handle == (void *)0) return -1;

  if (dlsym(handle, "mocktail_symbol_that_does_not_exist") != (void *)0) {
    return -2;
  }
  if (dlerror() == (char *)0) return -3;
  if (dlerror() != (char *)0) return -4;

  guest_dl_target_fn target =
      (guest_dl_target_fn)dlsym(handle, "guest_dl_target");
  if (target == (guest_dl_target_fn)0) return -5;

  struct DlInfo info = {0};
  if (dladdr((const void *)target, &info) != 1) return -7;
  if (info.dli_fname == (const char *)0 ||
      info.dli_fbase == (void *)0 ||
      info.dli_sname == (const char *)0 ||
      info.dli_saddr != (void *)target) return -8;
  if (info.dli_fname[0] != 'l' || info.dli_sname[0] != 'g') return -9;

  const int result = target(41);
  if (dlclose(handle) != 0) return -6;
  return result;
}
