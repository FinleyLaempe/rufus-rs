# rufus-rs — Architecture Design

- **Date:** 2026-09-25
- **Status:** Draft, awaiting review
- **Upstream baseline:** pbatard/rufus `942ed3a4` (master after 4.15, 2026-09-21)
- **Predecessor:** `~/Code/rufusLinux` (C port using a Win32-emulation layer). It is kept as a read-only reference and is not carried forward.

## 1. Goal

A **real, installable Linux product** that is a native Linux application and matches **the original Rufus 1:1** in features and behaviour. It is based on Rufus's source code and logic. The same codebase also builds a native Windows application. There is no Windows-specific code outside the platform and UI layers, and there are no feature compromises on either OS.

### Success criteria

1. Every behaviour in the parity inventory (§7) is implemented and tested on Linux, and then on Windows (M7).
2. Linux packages exist as `.deb`, `.rpm`, pacman (plus AUR) and Flatpak. Each installs and runs on its target distros.
3. It runs as a normal user. Raw disk access goes through UDisks2 and polkit only.
4. For every ISO in the parity corpus, the image report produced by `rufus-rs` matches the one produced by original Rufus.
5. Every filesystem it creates passes `fsck` on Linux and `chkdsk` on Windows.

### Non-goals

- Upstreaming to pbatard/rufus. This project is a separate fork.
- Reusing the Win32-emulation layer from `rufusLinux`.
- New features beyond upstream Rufus. Parity comes first; ideas go to a backlog.

## 2. Decisions and rationale

| # | Decision | Chosen | Rejected alternatives and why |
|---|----------|--------|-------------------------------|
| D1 | UI | **Two native UIs**: GTK4 on Linux and a Win32 dialog built from upstream's original resource on Windows. Both sit on one UI-agnostic core | A single GTK4 UI would feel alien on Windows. Qt6 would bring C++ into the project and move Windows away from the original dialog |
| D2 | Linux privileges | **UDisks2 + polkit**. The app runs unprivileged | Our own pkexec helper would mean maintaining a custom privileged protocol. Running the whole app as root means GTK under root, breaks on Wayland and fits Flatpak badly |
| D3 | Formatting | **Our own portable formatters on both OSes**, writing through one `BlockDevice` | Using fmifs.dll on Windows only would give two diverging code paths. UDisks2 `Format` cannot set Rufus's options (cluster size and others) |
| D4 | Strategy | **Clean rewrite**, using upstream as the behavioural and source reference | Refactoring the C port would leak Win32-isms into the core. Refactoring upstream in place was declined in favour of a clean design |
| D5 | Language | **Rust** | C would give easier line-for-line upstream ports but no memory safety in a tool that parses untrusted input and writes raw disks (this upstream sync alone fixed two heap OOB bugs). C++ has neither upstream fidelity nor safety |
| D6 | Dependencies | **Pure Rust from the start.** No C libraries: libcdio, wimlib, libext2fs, mkntfs and similar are all replaced by in-house crates | FFI behind traits was faster to ship but rejected in favour of a single clean stack |
| D7 | Writing files to filesystems | **Mount and copy.** Our crates *format*; the files are copied through the OS filesystem drivers (Linux kernel or Windows), exactly as Rufus does | Writing directly through our crates would roughly double the filesystem work, in the area where corruption bugs live |
| D8 | Sequencing | **Linux MVP first.** The Windows target compiles and runs its tests in CI from M1; the Windows backend and UI come in M7 | Building all libraries before any app would leave nothing usable for too long. Lockstep releases double the per-milestone cost |
| D9 | Repository | New public repo `FinleyLaempe/rufus-rs`, with `rufusLinux` kept as reference | Orphan branch or subdirectory in `rufusLinux` would mix codebases |
| D10 | Name | Working name **rufus-rs**. The public name is chosen before the first release. Credit reads "based on Rufus by Pete Batard" | Shipping as "Rufus" would need pbatard's permission |
| D11 | Licence | **GPL-3.0-or-later** (same as upstream, whose code and logic this derives from) | n/a |
| D12 | Settings storage | `rufus.ini`-compatible INI file on **both** OSes. No registry | Using the registry on Windows would hardcode Windows into the settings |

## 3. Architecture

```
rufus-rs/
  crates/
    rufus-core              Rufus logic: image analysis heuristics, option rules,
                            job pipeline, events. No OS APIs, no UI.
    rufus-blockdev          trait BlockDevice + FileDevice + MemDevice + OffsetDevice
    rufus-part              MBR / GPT read + write
    rufus-iso               ISO9660/Joliet/Rock Ridge/El Torito + UDF read
    rufus-fat               FAT12/16/32 format (+ cluster-chain read)
    rufus-ntfs              NTFS format
    rufus-exfat             exFAT format
    rufus-udf               UDF format
    rufus-ext               ext2/3/4 format
    rufus-wim               WIM read/extract/apply/split/update
    rufus-regf              Windows registry hive read/edit
    rufus-vhd               VHD / VHDX / FFU
    rufus-boot              MBR/PBR boot code, syslinux, GRUB4DOS/GRUB2, UEFI:NTFS, FreeDOS
    rufus-l10n              parser for upstream res/loc/rufus.loc
    rufus-net               update check, downloads, signature verification (rustls)
    rufus-platform          trait Platform
    rufus-platform-linux    UDisks2 (zbus) + sysfs
    rufus-platform-windows  windows-rs (M7)
  apps/
    rufus-gtk               GTK4 (plain, no libadwaita) — Linux UI
    rufus-win               Win32 UI from upstream's dialog resource (M7)
    rufus-cli               dev/test harness only: scan | write | hash
  xtask/                    cargo xtask upstream | data-sync | package
  data/                     synced upstream data: loc, bootloaders, DBX, FreeDOS, UFD tables
  packaging/                deb, rpm, arch, flatpak, desktop file, AppStream, icons
  docs/                     specs, plans, parity.md, upstream-tracking.md
```

### Layering rules

- Format and parser crates depend only on `rufus-blockdev` or on byte slices and readers. They never depend on the platform, UI or core.
- `rufus-core` depends on the format crates and on the `rufus-platform` **trait** only, never on a platform implementation or a UI crate.
- Apps wire a concrete platform implementation into the core and render its state.
- `#![forbid(unsafe_code)]` applies to every crate except `rufus-platform-*` and the two UI apps.
- Upstream data files (translations, bootloader binaries, DBX, FreeDOS, UFD/HDD tables) are reused **as data**, synced by `cargo xtask data-sync`.

## 4. Core model and core↔UI interaction

### State

`Session` holds:
- the device list (`Vec<Device>`);
- the scanned image (`ImageReport`, the counterpart of upstream `img_report`);
- the current `Options`.

### Option rules

These are pure functions: `constraints(&ImageReport, &Device, &Options) -> Constraints`. They return the allowed partition schemes, target systems, filesystems and cluster sizes, the defaults, and the enabled/visible state of each control. They replace upstream's `SetPartitionSchemeAndTargetSystem`, `SetFileSystemAndClusterSize`, `EnableControls` and related functions. Table-driven tests pin their behaviour to upstream.

### Jobs

Long-running operations are `Job`s on worker threads: scan, write/format, hash, bad blocks, download, update check. Each job communicates over a channel of `Event`s:

- `Progress { phase, done, total }`
- `Status(MsgId, Args)` and `Log(String)`
- `Prompt(Question, oneshot::Sender<Answer>)`. The job blocks until the UI answers. This covers upstream's mid-operation questions: ISO vs DD mode, downloading a newer ldlinux/GRUB, WUE options, destructive-operation confirmation, and so on.
- `Finished(Result<Summary, Error>)`

Cancellation uses a shared `CancelToken` that every loop checks (the counterpart of upstream `CHECK_FOR_USER_CANCEL`).

### UI adapters

GTK receives events through `glib::MainContext` channels. Win32 receives them through `PostMessage`. The UIs contain no Rufus logic.

### Text

The core emits upstream `MSG_xxx` IDs plus arguments. `rufus-l10n` formats them from `rufus.loc`, which gives all upstream languages including RTL.

### Errors

Each crate has typed errors (`thiserror`). The core maps them to the upstream user-facing messages.

### Settings

An INI file using upstream `rufus.ini` keys, stored at `$XDG_CONFIG_HOME/rufus-rs/` on Linux and `%APPDATA%\rufus-rs\` on Windows.

## 5. Platform layer

```rust
trait Platform {
    fn devices(&self) -> Result<Vec<Device>>;
    fn watch(&self) -> Receiver<DeviceEvent>;           // hotplug
    fn open(&self, dev: &DeviceId) -> Result<Box<dyn BlockDevice>>;
    fn unmount_all(&self, dev: &DeviceId) -> Result<()>;
    fn rescan(&self, dev: &DeviceId) -> Result<Vec<PartitionId>>;
    fn mount(&self, part: &PartitionId) -> Result<PathBuf>;
    fn unmount(&self, part: &PartitionId) -> Result<()>;
    fn settings_dir(&self) -> PathBuf;
}
```
(The exact signatures are settled in the M1 plan.)

### Linux (`rufus-platform-linux`), pure Rust via `zbus`

- **Enumeration and hotplug** use the UDisks2 `ObjectManager`: `Drive` objects (vendor, model, serial, size, removable, connection bus) and `Block` objects (device node, label), with the `InterfacesAdded`/`InterfacesRemoved` signals for hotplug. **USB VID:PID and port speed** are read from sysfs, which needs no privileges. Upstream's UFD-vs-HDD heuristic (`hdd_vs_ufd.h`) and its device filtering are ported into the core as data.
- **Opening the disk** uses `Block.OpenDevice("rw", {flags: O_EXCL})`, which returns an fd. polkit authenticates once. **The whole write runs through this single fd.** Partition tables and formatters write at partition offsets through `OffsetDevice`, as upstream does through the physical-drive handle.
- **Before writing:** `Filesystem.Unmount(force)` on each mounted partition. **After partitioning:** `Block.Rescan`, then wait for the partition objects, matched by offset. **For file copy:** `Filesystem.Mount` (as the user, under `/run/media/$USER`), copy, then `Unmount`. `rufus-ext` sets the ext root directory owner to the calling user's UID/GID.
- **Write path:** large aligned buffers (upstream uses 1–8 MB), `fsync` at phase ends, and a retry loop equivalent to upstream `WriteFileWithRetry`.

### Windows (`rufus-platform-windows`, M7)

SetupAPI and `IOCTL_STORAGE_*` for enumeration. `\\.\PhysicalDriveN` with `FSCTL_LOCK_VOLUME`/`FSCTL_DISMOUNT_VOLUME`, and `IOCTL_DISK_UPDATE_PROPERTIES` for rescans. Mounting uses a temporary **mount folder** (`SetVolumeMountPoint`), so no drive letters are needed. Elevation comes from the manifest (`requireAdministrator`), as in Rufus.

## 6. Filesystem and format crates

| Crate | Scope (driven by what upstream Rufus uses) |
|---|---|
| `rufus-part` | MBR/GPT read and write, MBR UEFI marker, extra partitions (ESP, UEFI:NTFS, persistence), upstream alignment rules |
| `rufus-fat` | FAT12/16/32 format, including upstream's large-FAT32 formatter (>32 GB) and its cluster-size rules. Enough read support for cluster chains, needed by the syslinux install (upstream uses libfat for this) |
| `rufus-ntfs` / `rufus-exfat` / `rufus-udf` | Format only, with every upstream cluster-size and label option and upstream's defaults |
| `rufus-ext` | ext2/3/4 format with the same features as upstream's libext2fs usage, root owner set, persistence (`casper-rw`, `persistence.conf`) |
| `rufus-iso` | Read-only: ISO9660 levels 1–3, Joliet, Rock Ridge, El Torito, UDF 1.02–2.60, multi-extent files >4 GB. Also compressed DD image input (gz/xz/bz2/zst/lzma) through pure-Rust decompressors |
| `rufus-wim` | Read, XPRESS/LZX/LZMS decompression, extract, apply-to-directory, XML/version info, split (for FAT32), and the update operations WUE needs (exact set defined in the M5 spec from upstream `wue.c`/`vhd.c`) |
| `rufus-regf`, `rufus-vhd`, `rufus-boot` | Scoped in their milestone specs from upstream usage |

Mature pure-Rust crates are used where they exist: RustCrypto (`sha1`, `sha2`, `md-5`, `rsa`); `flate2`, `xz2`/`lzma-rs`, `zstd`, `bzip2`; `rustls`/`ureq`; and `fatfs` inside `rufus-fat` if it passes our tests. Every crate is checked with Context7 and crates.io before it is adopted. Any crate that wraps C (for example `zstd`, `xz2`) is flagged in its milestone plan and replaced by a pure-Rust alternative (`ruzstd`, `lzma-rs`) if one is adequate. This is required by D6.

### Correctness gate

A format crate must pass all of the following before any release uses it:

1. **Differential tests.** Format the same image with our crate and with the reference tool (`mkfs.fat`, `mkntfs`, `mkfs.exfat`, `mkudffs`, `mke2fs`) using the same parameters. Parse both and compare layout fields; the only allowed differences are UUIDs and timestamps.
2. **fsck clean**, then **kernel mount + write/read stress + fsck again**.
3. **Property tests** (`proptest`): random sizes, cluster sizes and labels must all pass fsck.
4. **Fuzzing** (`cargo-fuzz`) of every parser: no panics, bounded allocation.
5. **Windows `chkdsk`** on NTFS/exFAT/UDF images in CI (Windows runner, images mounted as VHD) from the milestone that introduces each crate.

## 7. Parity with upstream

- **Parity inventory (`docs/parity.md`).** One row per upstream behaviour, taken from the **source**: every control and option, every prompt (`MSG_xxx` asked during an operation), every image-detection branch, and every write path. Each row records its upstream location (`file:function@commit`), the rufus-rs implementation, its test, and a status. A milestone is done when all of its rows are green.
- **Traceability markers.** Ported logic carries a marker comment: `// upstream: iso.c ExtractISO @942ed3a4`.
- **Upstream tracking (`docs/upstream-tracking.md` + `cargo xtask upstream`).** The xtask fetches pbatard/rufus, lists commits since the last one reviewed with the upstream files and functions they touched, and maps them through the markers to Rust files. Each commit gets one of three verdicts: **ported** (with the rufus-rs commit), **n/a** (with a reason) or **pending**. It runs at the end of every milestone and on every upstream release. `cargo xtask data-sync` updates `data/`.
- **Behavioural parity tests.** An ISO corpus (Ubuntu, Fedora, Debian, Arch, openSUSE, Windows 10/11, FreeDOS, and edge cases such as hybrid and multi-extent ISOs) is listed by URL and SHA-256, and kept outside the repo. **Golden files** come from original Rufus run in a Windows VM: its log image report and the offered options. `rufus-cli scan` emits the same report format, and CI diffs the two.
- **UI parity.** Manual screenshot comparison against the original at the end of each milestone.

## 8. Testing and CI (GitHub Actions; public repo)

| Trigger | Linux runner | Windows runner |
|---|---|---|
| Every PR | fmt, clippy `-D warnings`, unit + property tests, differential format tests, kernel-mount stress, UDisks2 loop-device tests of `rufus-platform-linux`, QEMU boot tests (OVMF + SeaBIOS; KVM if available, TCG otherwise) | build + unit tests; `chkdsk` on generated NTFS/exFAT/UDF images |
| Nightly | long `cargo-fuzz` runs; ISO-corpus parity diff (cached downloads) | — |
| Tag | build and smoke-test all packages (§9) | build the portable `.exe` |

Local and manual testing:
- The developer machine needs `qemu-desktop edk2-ovmf ntfs-3g 7zip` in addition to what is already installed.
- **Real hardware:** spare USB sticks and a PC to boot-test are available. Each milestone ends with a manual checklist run on them.
- **Windows VM:** used for golden files, parity checks and M7.

## 9. Packaging (Linux)

| Format | Tool | Verified by |
|---|---|---|
| `.deb` | `cargo-deb` | install + smoke test in Debian 13 and Ubuntu 24.04 containers |
| `.rpm` | `cargo-generate-rpm` | install + smoke test in a current Fedora container |
| pacman `.pkg.tar.zst` + AUR `PKGBUILD` (`rufus-rs-git`, versioned after the first release) | `makepkg` in an Arch container | install + smoke test |
| Flatpak (targeting Flathub) | `flatpak-builder` | install + smoke test; needs `--system-talk-name=org.freedesktop.UDisks2` and access to `/run/media` |

- All four share one `.desktop` file, AppStream metainfo and icons.
- Runtime dependencies: `gtk4 >= 4.14`, `udisks2`, `polkit`. No custom polkit policy, since UDisks2's own actions are used.
- The minimum GTK 4.14 covers Ubuntu 24.04+, Debian 13+, current Fedora and Arch.
- **Windows:** a single portable `.exe`, like Rufus. Code signing is deferred.

## 10. Milestones

Each milestone gets its own spec (where needed), plan and implementation cycle.

| M | Content |
|---|---|
| **M1** | **Linux MVP.** GTK4 main window 1:1 with the Rufus main dialog (every control, advanced sections, status bar, progress with phase text, toolbar: language/about/settings/log/hash; all languages including RTL). Devices and hotplug through UDisks2 with upstream filtering. DD image write (raw and compressed). ISO scan (ISO9660/Joliet/RR/El Torito) with the hybrid-ISO "ISO or DD" prompt. ISO → FAT32 on MBR/GPT for UEFI boot. Non-bootable FAT/FAT32 format. Hash dialog. Log window. INI settings. `rufus-cli`. CI incl. Windows build. **Spikes:** UDisks2 `OpenDevice` fd passing inside Flatpak, and `O_EXCL` flag support |
| M2 | `rufus-iso` UDF read + `rufus-ntfs`. Windows ISOs (>4 GB files), UEFI:NTFS, "Write as ESP" |
| M3 | `rufus-ext`, `rufus-exfat`, `rufus-udf`. Persistence partitions |
| M4 | `rufus-boot`: BIOS/CSM boot. syslinux (incl. version download logic), GRUB4DOS/GRUB2 (incl. core.img mismatch handling), FreeDOS, MS-DOS-style boot records |
| M5 | `rufus-wim` + `rufus-regf`: WUE customisation, Windows To Go. **Spike first:** applying a WIM to NTFS mounted on Linux while preserving security descriptors, reparse points and short names (see R2) |
| M6 | `rufus-vhd` (VHD/VHDX/FFU), bad-blocks check, downloads (Fido equivalent), update check, DBX handling |
| M7 | `rufus-platform-windows` + `rufus-win`. Full parity on Windows; golden-file diff on both OSes |

Packages (§9) are produced from M1 on. The first public *release* happens once the public name is chosen.

## 11. Risks

| # | Risk | Mitigation |
|---|---|---|
| R1 | Pure-Rust NTFS/exFAT/UDF/ext/WIM/regf is very large and correctness-critical | Correctness gate (§6), milestone ordering, `forbid(unsafe_code)`, fuzzing, Windows chkdsk in CI |
| R2 | Windows To Go on Linux: the kernel `ntfs3` and `ntfs-3g` drivers only partly expose NTFS security descriptors, reparse points and short names needed by WIM apply | M5 spike first. Fallback options are decided then; any gap is recorded in the parity inventory, never silently dropped |
| R3 | UDisks2 fd passing through the Flatpak D-Bus proxy, and `OpenDevice` flag support, across distro versions | M1 spike; checked against the UDisks2 versions in Ubuntu 24.04 / Debian 13 |
| R4 | Upstream drift: every upstream fix must be translated | Traceability markers + `cargo xtask upstream` + review at each milestone and upstream release |
| R5 | Name/branding confusion with official Rufus | Working name, prominent attribution, and the public name decided before the first release |
| R6 | Proprietary Microsoft formats (FFU, parts of WIM/LZMS) are under-documented | Use wimlib's documentation and source as the format reference. Its GPLv3+/LGPLv3+ licence is compatible with ours, so no clean-room process is needed. FFU is scoped in the M6 spec |

## 12. Open items

- The public project name (before the first release).
- The Flatpak app ID follows from the name.
