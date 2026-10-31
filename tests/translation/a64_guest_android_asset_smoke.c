// Copyright 2026 Mocktail Project Authors
// Licensed under the Apache License, Version 2.0.

typedef struct AAssetManager AAssetManager;
typedef struct AAsset AAsset;
typedef struct AConfiguration AConfiguration;

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

  AAsset* asset = AAssetManager_open(manager, kAssetPath, 0);
  if (asset == (AAsset*)0) return 4;

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
      readback[0] == '4' && readback[1] == '2' ? 42 : 5;
  AAsset_close(asset);
  return result;
}
