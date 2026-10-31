// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

typedef struct AAssetManager AAssetManager;
typedef struct AAsset AAsset;
typedef struct AConfiguration AConfiguration;
typedef struct ALooper ALooper;
typedef struct ANativeWindow ANativeWindow;

extern AAssetManager* AAssetManager_fromJava(void* env, void* manager);
extern AAsset* AAssetManager_open(AAssetManager* manager,
                                  const char* filename, int mode);
extern void AAsset_close(AAsset* asset);
extern const void* AAsset_getBuffer(AAsset* asset);
extern long AAsset_getLength(AAsset* asset);
extern long AAsset_seek(AAsset* asset, long offset, int whence);
extern int AAsset_read(AAsset* asset, void* buffer, unsigned long count);
extern AConfiguration* AConfiguration_new(void);
extern void AConfiguration_delete(AConfiguration* config);
extern void AConfiguration_fromAssetManager(AConfiguration* config,
                                            AAssetManager* manager);
extern void AConfiguration_getLanguage(AConfiguration* config, char* out);
extern void AConfiguration_getCountry(AConfiguration* config, char* out);
extern int AConfiguration_getScreenWidthDp(AConfiguration* config);
extern ALooper* ALooper_prepare(int options);
extern ALooper* ALooper_forThread(void);
extern void ALooper_release(ALooper* looper);
extern void ALooper_wake(ALooper* looper);
extern int ALooper_addFd(ALooper* looper, int fd, int ident, int events,
                         void* callback, void* data);
extern int ALooper_removeFd(ALooper* looper, int fd);
extern int ALooper_isPolling(ALooper* looper);
extern int ALooper_pollOnce(int timeout_ms, int* out_fd, int* out_events,
                            void** out_data);
extern ANativeWindow* ANativeWindow_fromSurface(void* env, void* surface);
extern void ANativeWindow_acquire(ANativeWindow* window);
extern void ANativeWindow_release(ANativeWindow* window);
extern int ANativeWindow_getWidth(ANativeWindow* window);
extern int ANativeWindow_getHeight(ANativeWindow* window);
extern int ANativeWindow_getFormat(ANativeWindow* window);
extern int ANativeWindow_setBuffersGeometry(ANativeWindow* window,
                                             int width, int height, int format);
extern int ANativeWindow_lock(ANativeWindow* window, void* out_buffer,
                              void* out_dirty);
extern int ANativeWindow_unlockAndPost(ANativeWindow* window);
extern int AndroidBitmap_getInfo(void* env, void* bitmap, void* info);
extern int AndroidBitmap_lockPixels(void* env, void* bitmap, void** pixels);
extern int AndroidBitmap_unlockPixels(void* env, void* bitmap);

static const char kAssetPath[] = "content/asset-smoke.txt";

__attribute__((visibility("default")))
int guest_android_asset_smoke(void) {
  AAssetManager* manager = AAssetManager_fromJava((void*)1, (void*)2);
  if (manager == (AAssetManager*)0) return 1;

  AConfiguration* config = AConfiguration_new();
  if (config == (AConfiguration*)0) return 2;
  AConfiguration_fromAssetManager(config, manager);
  char language[3] = {0, 0, 0};
  char country[3] = {0, 0, 0};
  AConfiguration_getLanguage(config, language);
  AConfiguration_getCountry(config, country);
  const int config_ok =
      language[0] == 'e' && language[1] == 'n' &&
      country[0] == 'U' && country[1] == 'S' &&
      AConfiguration_getScreenWidthDp(config) == 360;
  AConfiguration_delete(config);
  if (!config_ok) return 3;

  ALooper* looper = ALooper_prepare(1);
  if (looper == (ALooper*)0 || ALooper_forThread() != looper ||
      ALooper_isPolling(looper)) return 4;
  ALooper_wake(looper);
  int poll_fd = -1;
  int poll_events = -1;
  void* poll_data = (void*)1;
  const int poll_result =
      ALooper_pollOnce(0, &poll_fd, &poll_events, &poll_data);
  ALooper_release(looper);
  if (poll_result != -1 || poll_fd != 0 || poll_events != 0 ||
      poll_data != (void*)0) return 5;

  AAsset* asset = AAssetManager_open(manager, kAssetPath, 0);
  if (asset == (AAsset*)0) return 6;

  const long length = AAsset_getLength(asset);
  const unsigned char* buffer =
      (const unsigned char*)AAsset_getBuffer(asset);
  char readback[2] = {0, 0};
  const int seek_result = (int)AAsset_seek(asset, 0, 0);
  const int read_result = AAsset_read(asset, readback, sizeof(readback));
  const int result =
      length == 2 && buffer != (const unsigned char*)0 &&
      buffer[0] == '4' && buffer[1] == '2' &&
      seek_result == 0 && read_result == 2 &&
      readback[0] == '4' && readback[1] == '2' ? 42 : 7;
  AAsset_close(asset);
  return result;
}

__attribute__((visibility("default")))
int guest_android_looper_fd_smoke(int fd) {
  ALooper* looper = ALooper_prepare(1);
  if (looper == (ALooper*)0) return 1;
  if (ALooper_addFd(looper, fd, 17, 1, (void*)0, (void*)0x1234) != 1) {
    ALooper_release(looper);
    return 2;
  }
  int out_fd = -1;
  int out_events = 0;
  void* out_data = (void*)0;
  const int result = ALooper_pollOnce(0, &out_fd, &out_events, &out_data);
  const int removed = ALooper_removeFd(looper, fd);
  ALooper_release(looper);
  return result == 17 && out_fd == fd && (out_events & 1) != 0 &&
         out_data == (void*)0x1234 && removed == 1 ? 42 : 3;
}

__attribute__((visibility("default")))
int guest_android_headless_window_smoke(void) {
  ANativeWindow* window =
      ANativeWindow_fromSurface((void*)1, (void*)2);
  if (window != (ANativeWindow*)0) return 1;
  ANativeWindow_acquire(window);
  const int width = ANativeWindow_getWidth(window);
  const int height = ANativeWindow_getHeight(window);
  const int format = ANativeWindow_getFormat(window);
  const int geometry = ANativeWindow_setBuffersGeometry(window, 320, 240, 1);
  const int lock_result = ANativeWindow_lock(window, (void*)0, (void*)0);
  const int unlock_result = ANativeWindow_unlockAndPost(window);
  ANativeWindow_release(window);
  void* pixels = (void*)0;
  const int bitmap_info =
      AndroidBitmap_getInfo((void*)1, (void*)2, (void*)3);
  const int bitmap_lock =
      AndroidBitmap_lockPixels((void*)1, (void*)2, &pixels);
  const int bitmap_unlock =
      AndroidBitmap_unlockPixels((void*)1, (void*)2);
  return width == 0 && height == 0 && format == 0 &&
         geometry == -1 && lock_result == -1 && unlock_result == -1 &&
         bitmap_info == -1 && bitmap_lock == -1 && bitmap_unlock == -1
             ? 42 : 2;
}
