# Mocktail

[![CI](https://github.com/komaruworld/mocktail/actions/workflows/ci.yml/badge.svg)](https://github.com/komaruworld/mocktail/actions/workflows/ci.yml)
[![Stars](https://img.shields.io/github/stars/komaruworld/mocktail?style=flat&logo=github)](https://github.com/komaruworld/mocktail/stargazers)
[![Downloads](https://img.shields.io/github/downloads/komaruworld/mocktail/total?logo=github)](https://github.com/komaruworld/mocktail/releases/latest)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Discord](https://img.shields.io/discord/1543955607869063269?label=discord)](https://discord.gg/rhgpfcmFSD)

Mocktail runs the Android `x86_64` Roblox client on Linux and has experimental
`aarch64` builds for the Android `arm64-v8a` client. It also runs in a Linux
userspace hosted by FreeBSD's Linuxulator. Mocktail provides the Android ABI
and JNI pieces the client expects, then connects them to SDL3 and Vulkan or
OpenGL on the Linux side.

Mocktail is an independent community project. It is not affiliated with Roblox
Corporation or VinegarHQ and does not distribute the Roblox client.

## How it works

```
Roblox APK -> signature and ABI checks -> Bionic + JNI -> SDL3 + Vulkan/OpenGL
```

The APK is checked before any native code is loaded. It is downloaded on first
launch and is not bundled with Mocktail. The last working copy is kept in case
an update fails.

## Install with Flatpak

Install the stable release from Flathub:

```bash
flatpak install flathub space.bigrat.mocktail
flatpak run space.bigrat.mocktail
```

Nightly builds are produced automatically from the latest `main` branch:

```bash
flatpak install --user https://mocktail.bigrat.space/mocktail.flatpakref
flatpak run space.bigrat.mocktail
```

## Install from the AUR

Arch Linux users can install either the pinned source release (`mocktail`) or
the current development version (`mocktail-git`) with an AUR helper:

```bash
paru -S mocktail-git
# or
yay -S mocktail-git
```

Use `mocktail` instead of `mocktail-git` to build the pinned release from
source, or install the stable prebuilt package with `paru -S mocktail-bin` or
`yay -S mocktail-bin`.

## Install with DNF

Fedora 44 users can install either the stable `mocktail` package or the
`mocktail-nightly` package built from `main`:

```bash
sudo curl -fsSL https://mocktail.bigrat.space/rpm/mocktail.repo \
  -o /etc/yum.repos.d/mocktail.repo
sudo dnf install mocktail
# or
sudo dnf install mocktail-nightly
```

## Install with APT

Ubuntu 26.04 users can install either the stable `mocktail` package or the
`mocktail-nightly` package built from `main`:

```bash
sudo install -d -m 0755 /etc/apt/keyrings
sudo curl -fsSL https://mocktail.bigrat.space/mocktail-packages.gpg \
  -o /etc/apt/keyrings/mocktail.gpg
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/mocktail.gpg] https://mocktail.bigrat.space/apt mocktail main" | \
  sudo tee /etc/apt/sources.list.d/mocktail.list >/dev/null
sudo apt update
sudo apt install mocktail
# or
sudo apt install mocktail-nightly
```

## Direct downloads

Direct AppImage, DEB, and RPM downloads are available from the
[Website](https://mocktail.bigrat.space/) and
[GitHub Releases](https://github.com/komaruworld/mocktail/releases).

<details>
<summary>Screenshots</summary>

![Roblox home in Mocktail](assets/screenshots/flatpak-home.png)

![Roblox gameplay in Mocktail](assets/screenshots/flatpak-gameplay-tower.png)

![Roblox experience in Mocktail](assets/screenshots/flatpak-gameplay-lobby.png)

</details>

## FFlag overrides

Put a JSON object in `$XDG_CONFIG_HOME/mocktail/fflags.json` (usually
`~/.config/mocktail/fflags.json`). Mocktail applies it on the next launch.

PC profiles use the legacy Charts page by default to avoid the blank screen
caused by `Color3` errors in the newer SDUI page. An explicit
`FFlagLuaAppChartsAppPage` override takes precedence over this default.

```json
{
  "FFlagExample": "True",
  "DFIntExample": "120"
}
```
## FAQ

To see the most Frequently Asked Question go check [FAQ.md](FAQ.md)


## Experimental ARM64-on-x86 native probe

The `experimental/roblox-arm-translation` branch contains an opt-in
AArch64 guest runtime for x86-64 hosts. It uses Dynarmic to translate guest
instructions and has a bounded ELF loader, dependency resolver, sparse guest
memory, a limited Linux syscall dispatcher, static TLS support, and explicit
host-call thunks. It is separate from the normal Mocktail build.

On an x86-64 Linux host with Boost development headers installed, configure and
run its tests:

```bash
cmake -S . -B build-arm-translation \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DBUILD_TESTING=ON \
  -DMOCKTAIL_ENABLE_ROBLOX_ARM_TRANSLATION=ON
cmake --build build-arm-translation --parallel
ctest --test-dir build-arm-translation \
  -R 'RobloxArmTranslation' --output-on-failure
```

To inspect a real APK before attempting to load its native objects:

```bash
python3 tools/a64-elf-audit.py --json path/to/client.apk
python3 tools/mocktail-a64-apk-probe.py \
  --root libroblox.so path/to/client.apk
```

When an ELF declares a `DT_NEEDED` library that is not packaged in the APK,
you can explicitly allow that dependency name with a repeatable
`--external-dependency libNAME.so` option. This only tells the experimental
loader that the dependency is external; it does **not** implement the library
or resolve any missing symbols. Supply a matching Android ARM64 library with
`--library-dir PATH` whenever possible, and use the ELF audit report to
identify unresolved platform APIs rather than allowing dependencies blindly.

The probe extracts `lib/arm64-v8a/*.so` files and attempts to load the chosen
root library and its packaged dependency closure. You can pass a single APK, an
`.apks` bundle directly, or multiple split APKs as positional inputs. For
Android platform libraries not packaged with the app, provide matching ARM64
runtime libraries with repeated `--library-dir PATH` options; the APK input can
be omitted when using library directories alone. The loader currently requires
unambiguous library basenames.

By default, the probe loads the guest modules but does not call a guest
function. A known test entrypoint can be called explicitly with `--call SYMBOL`,
optional `--arg0` through `--arg7` register values, and a bounded
`--budget`. For raw `--call` entrypoints, `--run-initializers` is an explicit
opt-in to execute ELF constructors first. JNI-focused modes (`--jni-onload`
and `--call-native`) run dependency-ordered constructors automatically before
`JNI_OnLoad`, matching the required loader order. The current JNI bridge can
validate a limited `JNI_OnLoad`, track `RegisterNatives`, and invoke a registered
static native whose arguments fit in AArch64 registers. Do not treat an arbitrary
export as an application entrypoint: Java/ART objects and Android lifecycle
services are not generally available.

**This is not yet a complete Android APK launcher.** The prototype has only a
small explicit Bionic/libc/API shim set (including synthetic Android properties,
opaque `prop_info` reads, bounded `liblog` calls, static C++ guard words, and
single-context mutex no-ops) plus a narrow JNI test bridge. JavaVM attach/detach
slots do not create guest threads. It does not provide ART, a Java heap, Android
framework services, Activity lifecycle, real guest pthread scheduling,
runtime file-descriptor semantics, or Roblox graphics/window integration in
the AArch64 process. Real Roblox libraries may
still stop at unsupported relocations, unresolved imports, or runtime
assumptions that need real Android services. The probe is intended to turn those
failures into reproducible next steps; passing synthetic tests alone does not
mean Roblox is runnable.

## Building

Linux `x86_64` is supported. Linux `aarch64` builds are available, with Roblox
runtime validation still experimental. FreeBSD 15.1 Linuxulator support is
experimental and has been tested with an `x86_64` Fedora 44 userspace. On
FreeBSD, Mocktail runs inside Linuxulator; it is not a native FreeBSD binary.
Building requires CMake 3.20+, Git, pkg-config, LLD, binutils, a C++17
compiler, SDL 3.4+, SDL3_ttf,
Vulkan, EGL, libplacebo, fontconfig, libcurl, OpenSSL, libelf, libyaml, minizip,
Capstone 5, utf8proc, nlohmann/json, GTK4, libadwaita 1.6+, and WebKitGTK 6.0.

See the [FreeBSD Guide](packaging/freebsd/README.md) for setup and launch instructions.

<details>
<summary>Ubuntu 26.04+</summary>

```bash
sudo apt update
sudo apt install build-essential cmake git ninja-build pkg-config lld \
  libsdl3-dev libsdl3-ttf-dev libcurl4-openssl-dev libssl-dev \
  nlohmann-json3-dev libyaml-dev libelf-dev libminizip-dev \
  libcapstone-dev libgtk-4-dev libadwaita-1-dev libwebkitgtk-6.0-dev \
  libutf8proc-dev libfontconfig1-dev libegl-dev libvulkan-dev \
  libplacebo-dev libpng-dev zlib1g-dev
```
</details>

<details>
<summary>Arch Linux</summary>

```bash
sudo pacman -S --needed base-devel cmake git ninja pkgconf lld sdl3 sdl3_ttf \
  curl openssl nlohmann-json libyaml libelf minizip capstone gtk4 \
  libadwaita webkitgtk-6.0 libutf8proc fontconfig libglvnd \
  libplacebo vulkan-headers vulkan-icd-loader zlib
```
</details>

<details>
<summary>Fedora 44+</summary>

```bash
sudo dnf install gcc-c++ cmake git ninja-build pkgconf-pkg-config lld \
  SDL3-devel SDL3_ttf-devel libcurl-devel openssl-devel \
  nlohmann-json-devel libyaml-devel elfutils-libelf-devel minizip-ng-compat-devel \
  capstone-devel gtk4-devel libadwaita-devel webkitgtk6.0-devel \
  utf8proc-devel fontconfig-devel libglvnd-devel vulkan-headers \
  vulkan-loader-devel libplacebo-devel zlib-ng-compat-devel
```
</details>

```bash
git clone --recurse-submodules https://github.com/komaruworld/mocktail.git
cd mocktail
make build
./build/mocktail
```

## Known limitations

Mocktail does not currently work with `hardened_malloc`. Using
`hardened_malloc` may cause Mocktail to fail to start or crash during runtime.
Run Mocktail without `hardened_malloc` enabled.

## License

[Apache License 2.0](LICENSE). Third-party components keep their own licenses.

## Support

You can support the project by giving it a star or with cryptocurrency:

- USDT (TON): `UQCi6Yzcc9cOctoij6n_r1K90-OdVxAT0D_xo2UzGKkQaJDY`
- USDT (TRC20): `TNPMG9Vig2xiuo2r1QqnXRChPH7Vu28Jmx`
