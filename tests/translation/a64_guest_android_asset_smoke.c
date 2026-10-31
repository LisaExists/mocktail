// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

typedef struct AAssetManager AAssetManager;
typedef struct AAsset AAsset;

extern AAssetManager* AAssetManager_fromJava(void* env, void* manager);
extern AAsset* AAssetManager_open(AAssetManager* manager,
                                  const char* filename, int mode);
extern void AAsset_close(AAsset* asset);
extern const void* AAsset_getBuffer(AAsset* asset);
extern long AAsset_getLength(AAsset* asset);

static const char kAssetPath[] = "content/asset-smoke.txt";

__attribute__((visibility("default")))
int guest_android_asset_smoke(void) {
  AAssetManager* manager = AAssetManager_fromJava((void*)1, (void*)2);
  if (manager == (AAssetManager*)0) return 1;

  AAsset* asset = AAssetManager_open(manager, kAssetPath, 0);
  if (asset == (AAsset*)0) return 2;

  const long length = AAsset_getLength(asset);
  const unsigned char* buffer =
      (const unsigned char*)AAsset_getBuffer(asset);
  const int result =
      length == 2 && buffer != (const unsigned char*)0 &&
      buffer[0] == '4' && buffer[1] == '2' ? 42 : 3;
  AAsset_close(asset);
  return result;
}
