# M1a — Foundations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the rufus-rs Cargo workspace and the pure-Rust foundation crates for the Linux MVP: block devices, MBR/GPT with Rufus's partition layout, FAT16/FAT32 formatters, an ISO9660/Joliet/Rock Ridge/El Torito reader, hashing, localisation, and label rules. A developer CLI exercises them on image files, with no hardware needed.

**Architecture:** Every format crate reads and writes only through the `rufus_blockdev::BlockDevice` trait (or `Read + Seek` for ISO input), so it has no OS dependencies and is fully testable on image files. The logic is ported from upstream Rufus `942ed3a4`, and each ported function carries an `// upstream: file.c Function @942ed3a4` marker. M1b (platform + write pipeline) and M1c (GTK4 UI + packaging) build on these crates.

**Tech Stack:** Rust 2024 edition (toolchain 1.98 installed), Cargo workspace; `thiserror`, `crc32fast`, `uuid`, RustCrypto (`md-5`, `sha1`, `sha2`), `hex`, `clap`, `proptest`, `tempfile`, `serde_json`, `libfuzzer-sys`. External verification tools in tests: `sfdisk`, `sgdisk`, `fsck.fat`, `fatlabel`, `mtools`, `xorriso` (fixtures only).

**Spec:** `docs/superpowers/specs/2026-09-25-rufus-rs-architecture-design.md`

**Scope note:** The spec's M1 is split into three plans: **M1a** (this one: foundations), **M1b** (`rufus-platform-linux`, core jobs/events/option rules, DD and ISO→FAT32 write pipelines, loop-device + QEMU tests, Flatpak spike) and **M1c** (GTK4 UI, deb/rpm/pacman/Flatpak packaging). The spec's crate list does not name `rufus-hash`; this plan adds it as a small crate for MD5/SHA-1/SHA-256/SHA-512 (spec §6 names RustCrypto for hashing). The spec's `cargo xtask upstream` (commit-to-Rust mapping via markers) comes in M1b. M1a creates the tracking document and the markers it will read.

## Global Constraints

- Language/edition: Rust, `edition = "2024"`, `rust-version = "1.88"`, workspace `resolver = "3"`.
- Licence: `GPL-3.0-or-later` in every `Cargo.toml` (`license.workspace = true`).
- `#![forbid(unsafe_code)]` is enforced through `[workspace.lints.rust] unsafe_code = "forbid"`; every crate sets `[lints] workspace = true`.
- **Pure Rust only (spec D6):** no crate that links C code. All dependencies in this plan (`crc32fast`, `uuid`, RustCrypto, `hex`, `clap`, `thiserror`) are pure Rust.
- Format crates depend only on `rufus-blockdev`, `std`, and pure-Rust crates, never on platform or UI crates (spec §3 layering rules).
- Upstream baseline `942ed3a4`. Ported logic gets a comment `// upstream: <file>.c <Function> @942ed3a4`.
- Tests that call external tools (`sfdisk`, `sgdisk`, `fsck.fat`, `fatlabel`, `mtools`) live in files starting with `#![cfg(target_os = "linux")]`. Everything else must pass on the Windows CI runner.
- Clippy must pass with `cargo clippy --workspace --all-targets -- -D warnings`; `cargo fmt --all --check` must pass.
- Git on this machine has no `user.email`. Commit with `git -c user.name=FinleyLaempe -c user.email=finley.laempe@web.de commit ...` (all commit commands below assume this prefix, written as `git commit` for brevity).
- Dev machine test tools (Arch): `sudo pacman -S --needed libisoburn mtools gptfdisk dosfstools util-linux`. CI (Ubuntu): `xorriso mtools gdisk dosfstools fdisk`.

## Review Focus

1. **4 KiB-sector devices.** GPT, the layout planner and FAT32 must produce valid structures when `sector_size() == 4096` (GPT entry array spans 4 sectors, the FAT32 alignment unit is 256 sectors). Pinned by: Task 3 `gpt_roundtrip_4k`, Task 4 `gpt_4k_layout` + `apply_gpt_4k`, Task 5 `fat32_4k_sector_fsck`.
2. **Hostile or truncated ISO images.** Oversized record lengths, unterminated multi-extent files, Rock Ridge continuation loops and truncated files must return an `IsoError`, never panic or hang. Pinned by: Task 7 `record_length_overflow_is_corrupt`, `unterminated_multi_extent_is_corrupt`, `truncated_image_does_not_panic`; Task 9 `ce_loop_is_bounded`; Task 15 fuzz targets.
3. **Non-ASCII and emoji volume labels.** They must follow upstream `ToValidLabel` exactly (underscore substitution, then the size-based fallback label when the label is mostly underscores). Pinned by: Task 13 `fat_label_cjk_falls_back_to_size`, `fat_label_emoji_falls_back_to_size`.
4. **Disk sizes that aren't a multiple of the track or cluster size.** The planned partitions must never overlap, must stay sector-aligned, and must leave the GPT backup area free. Pinned by: Task 4 `mbr_uefi_ntfs_odd_disk_size` + proptest `layout_invariants`.
5. **FAT32 near the cluster-count limits.** Upstream's large-FAT32 algorithm rejects volumes with fewer than 65536 clusters (e.g. 256 MiB with the 4 KiB default). This must be a typed `TooFewClusters` error, not a malformed file system. Pinned by: Task 5 `fat32_256mib_default_is_too_few_clusters`. This is a known divergence from Windows `FormatEx` for FAT32 under 32 GB and is logged in `docs/parity.md` (Task 16).

## File Structure

```
Cargo.toml                         workspace manifest (members added per task)
rust-toolchain.toml                stable + rustfmt + clippy
.cargo/config.toml                 `cargo xtask` alias (Task 12)
.github/workflows/ci.yml           Linux + Windows CI (Task 1)
.github/workflows/fuzz.yml         nightly fuzzing (Task 15)
crates/rufus-blockdev/src/lib.rs   BlockDevice trait, MemDevice, FileDevice, OffsetDevice
crates/rufus-part/src/
  lib.rs                           re-exports
  error.rs                         PartError
  mbr.rs                           MBR table + CHS
  guid.rs                          GPT GUIDs + partition type constants
  gpt.rs                           GPT read/write
  layout.rs                        upstream CreatePartition port: plan_layout / apply_layout
crates/rufus-fat/src/
  lib.rs                           FatSummary, FatOptions, re-exports
  error.rs                         FatError
  time.rs                          LocalTime, DOS time, volume_id (GetVolumeID port)
  label.rs                         11-byte label + root-dir label entry
  fat32.rs                         FormatLargeFAT32 port
  fat16.rs                         FAT16 formatter (fatgen103 + upstream default cluster sizes)
crates/rufus-iso/src/
  lib.rs                           re-exports
  error.rs                         IsoError
  bytes.rs                         little-endian helpers
  volume.rs                        volume descriptors (PVD, Joliet SVD, boot record)
  record.rs                        directory records, multi-extent grouping, name translation
  susp.rs                          SUSP + Rock Ridge
  eltorito.rs                      El Torito boot catalog
  reader.rs                        IsoReader
crates/rufus-iso/tests/fixtures/   make-fixtures.sh + plain.iso, rrjoliet.iso, eltorito.iso
crates/rufus-hash/src/lib.rs       MultiHasher, Hashes, hash_reader
crates/rufus-l10n/src/
  lib.rs                           Catalog, embedded()
  parse.rs                         rufus.loc parser (parser.c port)
  printf.rs                        printf subset used by rufus.loc
  size.rs                          SizeToHumanReadable port
crates/rufus-core/src/lib.rs, label.rs   ToValidLabel port
apps/rufus-cli/src/main.rs         scan | hash | format-image
xtask/src/main.rs                  data-sync
data/loc/rufus.loc, data/UPSTREAM  synced upstream data
fuzz/                              cargo-fuzz targets (own workspace)
docs/parity.md, docs/upstream-tracking.md
```

---

### Task 1: Workspace, CI and `rufus-blockdev`

**Files:**
- Create: `Cargo.toml`, `rust-toolchain.toml`, `.gitignore`, `.github/workflows/ci.yml`
- Create: `crates/rufus-blockdev/Cargo.toml`, `crates/rufus-blockdev/src/lib.rs`
- Test: `crates/rufus-blockdev/src/lib.rs` (unit tests), `crates/rufus-blockdev/tests/file_device.rs`

**Interfaces:**
- Consumes: nothing.
- Produces (used by every later task):
  - `trait BlockDevice: Send { fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()>; fn write_at(&mut self, offset: u64, buf: &[u8]) -> io::Result<()>; fn len(&self) -> u64; fn sector_size(&self) -> u32; fn flush(&mut self) -> io::Result<()>; fn is_empty(&self) -> bool; fn write_zeros(&mut self, offset: u64, len: u64) -> io::Result<()>; }`
  - `MemDevice::new(len: usize, sector_size: u32)`, `MemDevice::from_vec(Vec<u8>, u32)`, `as_bytes()`, `as_bytes_mut()`, `into_vec()`
  - `FileDevice::open(&Path, writable: bool, sector_size: u32)`, `FileDevice::create(&Path, len: u64, sector_size: u32)`, `FileDevice::from_file(File, len, sector_size)`
  - `OffsetDevice::new(&'a mut dyn BlockDevice, offset: u64, len: u64) -> io::Result<OffsetDevice<'a>>`
  - `DEFAULT_SECTOR_SIZE: u32 = 512`
  - Out-of-range access returns `io::ErrorKind::UnexpectedEof`; offset overflow returns `io::ErrorKind::InvalidInput`.

- [ ] **Step 1: Create the workspace files**

`Cargo.toml`:
```toml
[workspace]
resolver = "3"
members = ["crates/rufus-blockdev"]
exclude = ["fuzz"]

[workspace.package]
version = "0.1.0"
edition = "2024"
license = "GPL-3.0-or-later"
repository = "https://github.com/FinleyLaempe/rufus-rs"
rust-version = "1.88"

[workspace.dependencies]
rufus-blockdev = { path = "crates/rufus-blockdev" }
thiserror = "2.0"
tempfile = "3.27"

[workspace.lints.rust]
unsafe_code = "forbid"

[workspace.lints.clippy]
all = { level = "warn", priority = -1 }
```

`rust-toolchain.toml`:
```toml
[toolchain]
channel = "stable"
components = ["rustfmt", "clippy"]
```

`.gitignore`:
```
/target
/fuzz/target
/fuzz/corpus
/fuzz/artifacts
```

`.github/workflows/ci.yml`:
```yaml
name: CI
on:
  push:
    branches: [main]
  pull_request:

env:
  CARGO_TERM_COLOR: always

jobs:
  linux:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy
      - uses: Swatinem/rust-cache@v2
      - name: Install verification tools
        run: sudo apt-get update && sudo apt-get install -y xorriso mtools gdisk dosfstools fdisk
      - run: cargo fmt --all --check
      - run: cargo clippy --workspace --all-targets -- -D warnings
      - run: cargo test --workspace

  windows:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - run: cargo build --workspace --all-targets
      - run: cargo test --workspace
```

`crates/rufus-blockdev/Cargo.toml`:
```toml
[package]
name = "rufus-blockdev"
description = "Block device abstraction for rufus-rs"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true

[dependencies]

[dev-dependencies]
tempfile.workspace = true

[lints]
workspace = true
```

- [ ] **Step 2: Write the failing tests**

`crates/rufus-blockdev/src/lib.rs` (tests only for now, plus an empty trait so the file compiles far enough to fail):
```rust
//! Block device abstraction shared by every rufus-rs format crate.

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn mem_roundtrip() {
        let mut d = MemDevice::new(4096, 512);
        d.write_at(100, b"hello").unwrap();
        let mut b = [0u8; 5];
        d.read_at(100, &mut b).unwrap();
        assert_eq!(&b, b"hello");
        assert_eq!(d.len(), 4096);
        assert_eq!(d.sector_size(), 512);
    }

    #[test]
    fn mem_rejects_out_of_range() {
        let mut d = MemDevice::new(1024, 512);
        assert_eq!(
            d.write_at(1020, b"hello").unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        let mut b = [0u8; 1];
        assert!(d.read_at(1024, &mut b).is_err());
        assert_eq!(
            d.read_at(u64::MAX, &mut b).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn write_zeros_spans_chunks() {
        let mut d = MemDevice::from_vec(vec![0xFF; 3 << 20], 512);
        let len = (2u64 << 20) + 5;
        d.write_zeros(10, len).unwrap();
        let bytes = d.as_bytes();
        assert_eq!(bytes[9], 0xFF);
        assert!(bytes[10..10 + len as usize].iter().all(|&b| b == 0));
        assert_eq!(bytes[10 + len as usize], 0xFF);
    }

    #[test]
    fn offset_device_translates_and_bounds() {
        let mut d = MemDevice::new(8192, 512);
        {
            let mut o = OffsetDevice::new(&mut d, 1024, 2048).unwrap();
            assert_eq!(o.len(), 2048);
            assert_eq!(o.sector_size(), 512);
            o.write_at(0, b"abc").unwrap();
            assert!(o.write_at(2046, b"abc").is_err());
        }
        assert_eq!(&d.as_bytes()[1024..1027], b"abc");
        assert!(OffsetDevice::new(&mut d, 8000, 500).is_err());
    }
}
```

`crates/rufus-blockdev/tests/file_device.rs`:
```rust
use rufus_blockdev::{BlockDevice, FileDevice};

#[test]
fn file_device_create_write_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("disk.img");
    {
        let mut d = FileDevice::create(&path, 1 << 20, 512).unwrap();
        assert_eq!(d.len(), 1 << 20);
        d.write_at(4096, b"rufus").unwrap();
        d.flush().unwrap();
    }
    let mut d = FileDevice::open(&path, false, 512).unwrap();
    let mut b = [0u8; 5];
    d.read_at(4096, &mut b).unwrap();
    assert_eq!(&b, b"rufus");
    assert!(d.read_at((1 << 20) - 2, &mut b).is_err());
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test -p rufus-blockdev`
Expected: compile errors `cannot find type MemDevice`, `unresolved import rufus_blockdev::FileDevice`.

- [ ] **Step 4: Implement `rufus-blockdev`**

Replace the top of `crates/rufus-blockdev/src/lib.rs` (keep the `#[cfg(test)] mod tests` block at the bottom):
```rust
//! Block device abstraction shared by every rufus-rs format crate.
//!
//! Format crates never talk to the operating system. They read and write
//! through [`BlockDevice`], so the same code runs against a Linux UDisks2 fd,
//! a Windows physical-drive handle, an image file, or memory.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

/// Sector size assumed for plain image files.
pub const DEFAULT_SECTOR_SIZE: u32 = 512;

const ZERO_CHUNK: u64 = 1 << 20;

/// A random-access, fixed-size block device.
pub trait BlockDevice: Send {
    /// Fills `buf` with the bytes starting at `offset`.
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()>;
    /// Writes all of `buf` starting at `offset`.
    fn write_at(&mut self, offset: u64, buf: &[u8]) -> io::Result<()>;
    /// Size of the device in bytes.
    fn len(&self) -> u64;
    /// Logical sector size in bytes.
    fn sector_size(&self) -> u32;
    /// Flushes pending writes to stable storage.
    fn flush(&mut self) -> io::Result<()>;

    /// Returns `true` if the device has a size of zero.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Writes `len` zero bytes starting at `offset`.
    fn write_zeros(&mut self, offset: u64, len: u64) -> io::Result<()> {
        let zeros = vec![0u8; len.min(ZERO_CHUNK) as usize];
        let mut done = 0;
        while done < len {
            let n = (len - done).min(ZERO_CHUNK) as usize;
            self.write_at(offset + done, &zeros[..n])?;
            done += n as u64;
        }
        Ok(())
    }
}

impl<T: BlockDevice + ?Sized> BlockDevice for &mut T {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        (**self).read_at(offset, buf)
    }
    fn write_at(&mut self, offset: u64, buf: &[u8]) -> io::Result<()> {
        (**self).write_at(offset, buf)
    }
    fn len(&self) -> u64 {
        (**self).len()
    }
    fn sector_size(&self) -> u32 {
        (**self).sector_size()
    }
    fn flush(&mut self) -> io::Result<()> {
        (**self).flush()
    }
    fn write_zeros(&mut self, offset: u64, len: u64) -> io::Result<()> {
        (**self).write_zeros(offset, len)
    }
}

impl<T: BlockDevice + ?Sized> BlockDevice for Box<T> {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        (**self).read_at(offset, buf)
    }
    fn write_at(&mut self, offset: u64, buf: &[u8]) -> io::Result<()> {
        (**self).write_at(offset, buf)
    }
    fn len(&self) -> u64 {
        (**self).len()
    }
    fn sector_size(&self) -> u32 {
        (**self).sector_size()
    }
    fn flush(&mut self) -> io::Result<()> {
        (**self).flush()
    }
    fn write_zeros(&mut self, offset: u64, len: u64) -> io::Result<()> {
        (**self).write_zeros(offset, len)
    }
}

fn check_range(offset: u64, len: usize, size: u64) -> io::Result<()> {
    let end = offset
        .checked_add(len as u64)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "offset overflow"))?;
    if end > size {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("access {offset}..{end} is beyond the device end ({size})"),
        ));
    }
    Ok(())
}

/// An in-memory block device, used by tests.
#[derive(Debug, Clone)]
pub struct MemDevice {
    data: Vec<u8>,
    sector_size: u32,
}

impl MemDevice {
    /// Creates a zero-filled device of `len` bytes.
    pub fn new(len: usize, sector_size: u32) -> Self {
        Self::from_vec(vec![0; len], sector_size)
    }

    /// Wraps existing bytes.
    pub fn from_vec(data: Vec<u8>, sector_size: u32) -> Self {
        Self { data, sector_size }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.data
    }
}

impl BlockDevice for MemDevice {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        check_range(offset, buf.len(), self.len())?;
        let start = offset as usize;
        buf.copy_from_slice(&self.data[start..start + buf.len()]);
        Ok(())
    }
    fn write_at(&mut self, offset: u64, buf: &[u8]) -> io::Result<()> {
        check_range(offset, buf.len(), self.len())?;
        let start = offset as usize;
        self.data[start..start + buf.len()].copy_from_slice(buf);
        Ok(())
    }
    fn len(&self) -> u64 {
        self.data.len() as u64
    }
    fn sector_size(&self) -> u32 {
        self.sector_size
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A block device backed by a file: an image file, or an OS device handle
/// handed over by a platform backend.
#[derive(Debug)]
pub struct FileDevice {
    file: File,
    len: u64,
    sector_size: u32,
}

impl FileDevice {
    /// Opens an existing file. Its current size becomes the device size.
    pub fn open(path: &Path, writable: bool, sector_size: u32) -> io::Result<Self> {
        let file = OpenOptions::new().read(true).write(writable).open(path)?;
        let len = file.metadata()?.len();
        Ok(Self::from_file(file, len, sector_size))
    }

    /// Creates (or truncates) a file of exactly `len` bytes.
    pub fn create(path: &Path, len: u64, sector_size: u32) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        file.set_len(len)?;
        Ok(Self::from_file(file, len, sector_size))
    }

    /// Wraps an already-open file or device of known size.
    pub fn from_file(file: File, len: u64, sector_size: u32) -> Self {
        Self {
            file,
            len,
            sector_size,
        }
    }
}

impl BlockDevice for FileDevice {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        check_range(offset, buf.len(), self.len)?;
        read_exact_at(&self.file, buf, offset)
    }
    fn write_at(&mut self, offset: u64, buf: &[u8]) -> io::Result<()> {
        check_range(offset, buf.len(), self.len)?;
        write_all_at(&self.file, buf, offset)
    }
    fn len(&self) -> u64 {
        self.len
    }
    fn sector_size(&self) -> u32 {
        self.sector_size
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.sync_all()
    }
}

#[cfg(unix)]
fn read_exact_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.read_exact_at(buf, offset)
}

#[cfg(unix)]
fn write_all_at(file: &File, buf: &[u8], offset: u64) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.write_all_at(buf, offset)
}

#[cfg(windows)]
fn read_exact_at(file: &File, mut buf: &mut [u8], mut offset: u64) -> io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        let n = file.seek_read(buf, offset)?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        buf = &mut buf[n..];
        offset += n as u64;
    }
    Ok(())
}

#[cfg(windows)]
fn write_all_at(file: &File, mut buf: &[u8], mut offset: u64) -> io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        let n = file.seek_write(buf, offset)?;
        if n == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        buf = &buf[n..];
        offset += n as u64;
    }
    Ok(())
}

/// A window onto part of another device, e.g. one partition of a disk.
pub struct OffsetDevice<'a> {
    inner: &'a mut dyn BlockDevice,
    offset: u64,
    len: u64,
}

impl fmt::Debug for OffsetDevice<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OffsetDevice")
            .field("offset", &self.offset)
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

impl<'a> OffsetDevice<'a> {
    /// Exposes `len` bytes of `inner` starting at `offset`.
    pub fn new(inner: &'a mut dyn BlockDevice, offset: u64, len: u64) -> io::Result<Self> {
        let end = offset
            .checked_add(len)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "offset overflow"))?;
        if end > inner.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "window extends beyond the device end",
            ));
        }
        Ok(Self { inner, offset, len })
    }
}

impl BlockDevice for OffsetDevice<'_> {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        check_range(offset, buf.len(), self.len)?;
        self.inner.read_at(self.offset + offset, buf)
    }
    fn write_at(&mut self, offset: u64, buf: &[u8]) -> io::Result<()> {
        check_range(offset, buf.len(), self.len)?;
        self.inner.write_at(self.offset + offset, buf)
    }
    fn len(&self) -> u64 {
        self.len
    }
    fn sector_size(&self) -> u32 {
        self.inner.sector_size()
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
```

- [ ] **Step 5: Run the tests and lints**

Run: `cargo test -p rufus-blockdev && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all --check`
Expected: 5 tests pass, no clippy warnings, fmt clean.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml rust-toolchain.toml .gitignore .github crates/rufus-blockdev
git commit -m "feat(blockdev): workspace, CI and BlockDevice abstraction"
git push
```
Check that the pushed CI run passes on both Linux and Windows: `gh run watch --exit-status`.

---

### Task 2: `rufus-part` — MBR

**Files:**
- Create: `crates/rufus-part/Cargo.toml`, `crates/rufus-part/src/lib.rs`, `crates/rufus-part/src/error.rs`, `crates/rufus-part/src/mbr.rs`
- Modify: `Cargo.toml` (members, workspace deps)
- Test: unit tests in `mbr.rs`; `crates/rufus-part/tests/sfdisk_mbr.rs`

**Interfaces:**
- Consumes: `rufus_blockdev::BlockDevice`, `MemDevice`, `FileDevice`.
- Produces:
  - `pub enum PartError { Io(io::Error), NoMbrSignature, NoGpt, GptHeaderCrc, GptEntriesCrc, InvalidRequest(&'static str), DiskTooSmall, MbrOverflow(usize) }`
  - `pub struct MbrPartition { pub bootable: bool, pub part_type: u8, pub start_lba: u32, pub sectors: u32 }` (Copy)
  - `pub struct Mbr { pub disk_signature: u32, pub partitions: [Option<MbrPartition>; 4] }` with `to_sector(&self, sector_size: u32) -> Vec<u8>`, `parse(&[u8]) -> Result<Mbr, PartError>`, `read(&mut dyn BlockDevice)`, `write(&self, &mut dyn BlockDevice)`
  - `pub fn lba_to_chs(lba: u64) -> [u8; 3]`, `pub const MBR_UEFI_MARKER: u32 = 0x4946_5545`

- [ ] **Step 1: Add the crate to the workspace**

In the root `Cargo.toml`, change `members` and add dependencies:
```toml
members = ["crates/rufus-blockdev", "crates/rufus-part"]
```
```toml
[workspace.dependencies]
rufus-blockdev = { path = "crates/rufus-blockdev" }
rufus-part = { path = "crates/rufus-part" }
thiserror = "2.0"
tempfile = "3.27"
serde_json = "1.0"
crc32fast = "1.5"
uuid = { version = "1.26", features = ["v4"] }
proptest = "1.11"
```

`crates/rufus-part/Cargo.toml`:
```toml
[package]
name = "rufus-part"
description = "MBR/GPT partition tables and the Rufus partition layout planner"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true

[dependencies]
rufus-blockdev.workspace = true
thiserror.workspace = true
crc32fast.workspace = true
uuid.workspace = true

[dev-dependencies]
tempfile.workspace = true
serde_json.workspace = true
proptest.workspace = true

[lints]
workspace = true
```

`crates/rufus-part/src/error.rs`:
```rust
use std::io;

/// Errors from partition-table reading, writing and layout planning.
#[derive(Debug, thiserror::Error)]
pub enum PartError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("no valid MBR signature (0x55AA) found")]
    NoMbrSignature,
    #[error("no valid GPT header found")]
    NoGpt,
    #[error("GPT header CRC mismatch")]
    GptHeaderCrc,
    #[error("GPT partition entry array CRC mismatch")]
    GptEntriesCrc,
    #[error("invalid layout request: {0}")]
    InvalidRequest(&'static str),
    #[error("the disk is too small for the requested layout")]
    DiskTooSmall,
    #[error("partition {0} does not fit in 32-bit MBR fields")]
    MbrOverflow(usize),
}
```

`crates/rufus-part/src/lib.rs`:
```rust
//! MBR and GPT partition tables, and Rufus's partition layout planner.

mod error;
mod mbr;

pub use error::PartError;
pub use mbr::{MBR_UEFI_MARKER, Mbr, MbrPartition, lba_to_chs};
```

- [ ] **Step 2: Write the failing tests**

`crates/rufus-part/src/mbr.rs` (tests first):
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use rufus_blockdev::MemDevice;

    #[test]
    fn chs_values() {
        assert_eq!(lba_to_chs(0), [0, 1, 0]);
        assert_eq!(lba_to_chs(2048), [32, 33, 0]);
        // cylinder 1023 is the last encodable one; beyond that Windows writes FE FF FF
        assert_eq!(lba_to_chs(1024 * 255 * 63), [0xFE, 0xFF, 0xFF]);
    }

    #[test]
    fn serialises_entries_and_signature() {
        let mbr = Mbr {
            disk_signature: 0x1234_5678,
            partitions: [
                Some(MbrPartition { bootable: true, part_type: 0x0c, start_lba: 2048, sectors: 4096 }),
                None,
                None,
                None,
            ],
        };
        let s = mbr.to_sector(512);
        assert_eq!(s.len(), 512);
        assert_eq!(&s[0x1B8..0x1BC], &[0x78, 0x56, 0x34, 0x12]);
        assert_eq!(s[0x1BE], 0x80);
        assert_eq!(s[0x1BE + 4], 0x0c);
        assert_eq!(&s[0x1BE + 8..0x1BE + 12], &2048u32.to_le_bytes());
        assert_eq!(&s[0x1BE + 12..0x1BE + 16], &4096u32.to_le_bytes());
        assert_eq!(&s[510..512], &[0x55, 0xAA]);
        assert!(s[0x1CE..0x1FE].iter().all(|&b| b == 0));
    }

    #[test]
    fn roundtrip_through_device() {
        let mut dev = MemDevice::new(1 << 20, 512);
        let mbr = Mbr {
            disk_signature: MBR_UEFI_MARKER,
            partitions: [
                Some(MbrPartition { bootable: false, part_type: 0x07, start_lba: 2048, sectors: 1000 }),
                Some(MbrPartition { bootable: false, part_type: 0xef, start_lba: 3048, sectors: 64 }),
                None,
                None,
            ],
        };
        mbr.write(&mut dev).unwrap();
        assert_eq!(Mbr::read(&mut dev).unwrap(), mbr);
    }

    #[test]
    fn missing_signature_is_an_error() {
        let sector = vec![0u8; 512];
        assert!(matches!(Mbr::parse(&sector), Err(PartError::NoMbrSignature)));
        assert!(matches!(Mbr::parse(&sector[..100]), Err(PartError::NoMbrSignature)));
    }
}
```

`crates/rufus-part/tests/sfdisk_mbr.rs`:
```rust
#![cfg(target_os = "linux")]

use rufus_blockdev::FileDevice;
use rufus_part::{Mbr, MbrPartition};
use std::process::Command;

#[test]
fn sfdisk_reads_our_mbr() {
    let dir = tempfile::tempdir().unwrap();
    let img = dir.path().join("mbr.img");
    let mut dev = FileDevice::create(&img, 64 << 20, 512).unwrap();
    let mbr = Mbr {
        disk_signature: 0x1234_5678,
        partitions: [
            Some(MbrPartition { bootable: true, part_type: 0x0c, start_lba: 2048, sectors: 100_000 }),
            None,
            None,
            None,
        ],
    };
    mbr.write(&mut dev).unwrap();
    drop(dev);

    let out = Command::new("sfdisk").arg("-J").arg(&img).output().expect("sfdisk is installed");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let table = &v["partitiontable"];
    assert_eq!(table["label"], "dos");
    assert_eq!(table["id"], "0x12345678");
    let p = &table["partitions"][0];
    assert_eq!(p["start"], 2048);
    assert_eq!(p["size"], 100_000);
    assert_eq!(p["type"], "c");
    assert_eq!(p["bootable"], true);
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test -p rufus-part`
Expected: compile errors, `Mbr`/`lba_to_chs` not found.

- [ ] **Step 4: Implement the MBR**

Put this above the tests in `crates/rufus-part/src/mbr.rs`:
```rust
use crate::PartError;
use rufus_blockdev::BlockDevice;

/// 'U','E','F','I' as a little-endian u32. Rufus writes it as the MBR disk
/// signature for MBR+UEFI drives. upstream: rufus.h MBR_UEFI_MARKER @942ed3a4
pub const MBR_UEFI_MARKER: u32 = 0x4946_5545;

const TABLE_OFFSET: usize = 0x1BE;
const HEADS: u64 = 255;
const SECTORS_PER_TRACK: u64 = 63;

/// One primary MBR partition entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MbrPartition {
    pub bootable: bool,
    pub part_type: u8,
    pub start_lba: u32,
    pub sectors: u32,
}

/// A classic MBR partition table (boot code is not handled here).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Mbr {
    pub disk_signature: u32,
    pub partitions: [Option<MbrPartition>; 4],
}

/// Converts an LBA to the packed CHS triple for a 255-head, 63-sector
/// geometry, the one Windows reports for USB drives.
pub fn lba_to_chs(lba: u64) -> [u8; 3] {
    let cylinder = lba / (HEADS * SECTORS_PER_TRACK);
    if cylinder > 1023 {
        return [0xFE, 0xFF, 0xFF];
    }
    let head = (lba / SECTORS_PER_TRACK) % HEADS;
    let sector = lba % SECTORS_PER_TRACK + 1;
    [
        head as u8,
        (sector as u8) | (((cylinder >> 2) & 0xC0) as u8),
        (cylinder & 0xFF) as u8,
    ]
}

impl Mbr {
    /// Serialises the table into a sector of `sector_size` bytes. The boot
    /// code area is left zeroed; bootloaders are written separately.
    pub fn to_sector(&self, sector_size: u32) -> Vec<u8> {
        let mut s = vec![0u8; sector_size.max(512) as usize];
        s[0x1B8..0x1BC].copy_from_slice(&self.disk_signature.to_le_bytes());
        for (i, p) in self.partitions.iter().enumerate() {
            let Some(p) = p else { continue };
            let e = &mut s[TABLE_OFFSET + i * 16..TABLE_OFFSET + (i + 1) * 16];
            e[0] = if p.bootable { 0x80 } else { 0x00 };
            e[1..4].copy_from_slice(&lba_to_chs(u64::from(p.start_lba)));
            e[4] = p.part_type;
            let last = (u64::from(p.start_lba) + u64::from(p.sectors)).saturating_sub(1);
            e[5..8].copy_from_slice(&lba_to_chs(last));
            e[8..12].copy_from_slice(&p.start_lba.to_le_bytes());
            e[12..16].copy_from_slice(&p.sectors.to_le_bytes());
        }
        s[510] = 0x55;
        s[511] = 0xAA;
        s
    }

    /// Parses sector 0. Entries with partition type 0 are empty.
    pub fn parse(sector: &[u8]) -> Result<Mbr, PartError> {
        if sector.len() < 512 || sector[510] != 0x55 || sector[511] != 0xAA {
            return Err(PartError::NoMbrSignature);
        }
        let le32 = |b: &[u8]| u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        let mut partitions = [None; 4];
        for (i, slot) in partitions.iter_mut().enumerate() {
            let e = &sector[TABLE_OFFSET + i * 16..TABLE_OFFSET + (i + 1) * 16];
            if e[4] == 0 {
                continue;
            }
            *slot = Some(MbrPartition {
                bootable: e[0] == 0x80,
                part_type: e[4],
                start_lba: le32(&e[8..12]),
                sectors: le32(&e[12..16]),
            });
        }
        Ok(Mbr { disk_signature: le32(&sector[0x1B8..0x1BC]), partitions })
    }

    /// Reads and parses sector 0 of `dev`.
    pub fn read(dev: &mut dyn BlockDevice) -> Result<Mbr, PartError> {
        let mut s = vec![0u8; dev.sector_size().max(512) as usize];
        dev.read_at(0, &mut s)?;
        Mbr::parse(&s)
    }

    /// Writes the table as sector 0 of `dev`.
    pub fn write(&self, dev: &mut dyn BlockDevice) -> Result<(), PartError> {
        dev.write_at(0, &self.to_sector(dev.sector_size()))?;
        Ok(())
    }
}
```

- [ ] **Step 5: Run the tests**

Run: `cargo test -p rufus-part`
Expected: 4 unit tests + `sfdisk_reads_our_mbr` pass.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml crates/rufus-part
git commit -m "feat(part): MBR partition table read/write"
```

---

### Task 3: `rufus-part` — GUIDs and GPT

**Files:**
- Create: `crates/rufus-part/src/guid.rs`, `crates/rufus-part/src/gpt.rs`
- Modify: `crates/rufus-part/src/lib.rs`
- Test: unit tests in `guid.rs` and `gpt.rs`; `crates/rufus-part/tests/sgdisk_gpt.rs`

**Interfaces:**
- Consumes: `Mbr`, `MbrPartition`, `PartError` (Task 2), `BlockDevice`, `MemDevice`, `FileDevice` (Task 1).
- Produces:
  - `pub struct Guid(pub [u8; 16])` (on-disk mixed-endian byte order), `Guid::ZERO`, `const fn Guid::from_fields(u32, u16, u16, [u8; 8])`, `Guid::random()`, `Display` as `XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX`
  - `pub fn random_u32() -> u32`
  - `pub mod types { ESP, LINUX_DATA, MICROSOFT_DATA, MICROSOFT_RESERVED }`, `pub const GPT_BASIC_DATA_ATTRIBUTE_NO_DRIVE_LETTER: u64`
  - `pub struct GptPartition { pub type_guid: Guid, pub unique_guid: Guid, pub first_lba: u64, pub last_lba: u64, pub attributes: u64, pub name: String }`
  - `pub struct Gpt { pub disk_guid: Guid, pub partitions: Vec<GptPartition> }` with `write(&self, &mut dyn BlockDevice) -> Result<(), PartError>`, `read(&mut dyn BlockDevice) -> Result<Gpt, PartError>`
  - `GPT_ENTRIES = 128`, `GPT_ENTRY_SIZE = 128`, `GPT_FIRST_USABLE_LBA = 34`. The last usable LBA is `total_sectors - 34`.

- [ ] **Step 1: Write the failing tests**

`crates/rufus-part/src/guid.rs` (tests):
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn esp_guid_layout_and_display() {
        assert_eq!(&types::ESP.0[..4], &[0x28, 0x73, 0x2A, 0xC1]);
        assert_eq!(types::ESP.to_string(), "C12A7328-F81F-11D2-BA4B-00A0C93EC93B");
        assert_eq!(
            types::MICROSOFT_DATA.to_string(),
            "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"
        );
    }

    #[test]
    fn random_guids_differ_and_are_version_4() {
        let a = Guid::random();
        let b = Guid::random();
        assert_ne!(a, b);
        // version nibble lives in the high nibble of d3 (byte 7 on disk)
        assert_eq!(a.0[7] >> 4, 4);
    }
}
```

`crates/rufus-part/src/gpt.rs` (tests):
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::types;
    use rufus_blockdev::MemDevice;

    fn sample(ss: u64, total: u64) -> Gpt {
        Gpt {
            disk_guid: Guid::random(),
            partitions: vec![
                GptPartition {
                    type_guid: types::ESP,
                    unique_guid: Guid::random(),
                    first_lba: (1 << 20) / ss,
                    last_lba: (2 << 20) / ss - 1,
                    attributes: 0,
                    name: "EFI System Partition".into(),
                },
                GptPartition {
                    type_guid: types::MICROSOFT_DATA,
                    unique_guid: Guid::random(),
                    first_lba: (2 << 20) / ss,
                    last_lba: total - GPT_FIRST_USABLE_LBA,
                    attributes: crate::GPT_BASIC_DATA_ATTRIBUTE_NO_DRIVE_LETTER,
                    name: "Main Data Partition".into(),
                },
            ],
        }
    }

    fn roundtrip(ss: u32) {
        let len = 64u64 << 20;
        let mut dev = MemDevice::new(len as usize, ss);
        let gpt = sample(u64::from(ss), len / u64::from(ss));
        gpt.write(&mut dev).unwrap();
        assert_eq!(Gpt::read(&mut dev).unwrap(), gpt);

        let total = len / u64::from(ss);
        let bytes = dev.as_bytes();
        // protective MBR
        assert_eq!(bytes[0x1BE + 4], 0xEE);
        assert_eq!(&bytes[510..512], &[0x55, 0xAA]);
        // primary header points at the backup header in the last sector
        let hdr = &bytes[ss as usize..2 * ss as usize];
        assert_eq!(&hdr[0..8], b"EFI PART");
        assert_eq!(u64::from_le_bytes(hdr[32..40].try_into().unwrap()), total - 1);
        let backup = &bytes[((total - 1) * u64::from(ss)) as usize..];
        assert_eq!(&backup[0..8], b"EFI PART");
        assert_eq!(u64::from_le_bytes(backup[24..32].try_into().unwrap()), total - 1);
    }

    #[test]
    fn gpt_roundtrip_512() {
        roundtrip(512);
    }

    #[test]
    fn gpt_roundtrip_4k() {
        roundtrip(4096);
    }

    #[test]
    fn corrupt_header_is_detected() {
        let mut dev = MemDevice::new(64 << 20, 512);
        sample(512, (64 << 20) / 512).write(&mut dev).unwrap();
        dev.as_bytes_mut()[512 + 40] ^= 0xFF;
        assert!(matches!(Gpt::read(&mut dev), Err(PartError::GptHeaderCrc)));
    }

    #[test]
    fn corrupt_entries_are_detected() {
        let mut dev = MemDevice::new(64 << 20, 512);
        sample(512, (64 << 20) / 512).write(&mut dev).unwrap();
        dev.as_bytes_mut()[2 * 512 + 60] ^= 0xFF;
        assert!(matches!(Gpt::read(&mut dev), Err(PartError::GptEntriesCrc)));
    }

    #[test]
    fn blank_disk_has_no_gpt() {
        let mut dev = MemDevice::new(1 << 20, 512);
        assert!(matches!(Gpt::read(&mut dev), Err(PartError::NoGpt)));
    }

    #[test]
    fn partition_outside_usable_area_is_rejected() {
        let mut dev = MemDevice::new(64 << 20, 512);
        let mut gpt = sample(512, (64 << 20) / 512);
        gpt.partitions[1].last_lba = (64 << 20) / 512 - 1;
        assert!(matches!(gpt.write(&mut dev), Err(PartError::InvalidRequest(_))));
    }
}
```

`crates/rufus-part/tests/sgdisk_gpt.rs`:
```rust
#![cfg(target_os = "linux")]

use rufus_blockdev::FileDevice;
use rufus_part::{GPT_FIRST_USABLE_LBA, Gpt, GptPartition, Guid, types};
use std::process::Command;

#[test]
fn sgdisk_and_sfdisk_accept_our_gpt() {
    let dir = tempfile::tempdir().unwrap();
    let img = dir.path().join("gpt.img");
    let len: u64 = 128 << 20;
    let total = len / 512;
    let mut dev = FileDevice::create(&img, len, 512).unwrap();
    let gpt = Gpt {
        disk_guid: Guid::random(),
        partitions: vec![GptPartition {
            type_guid: types::MICROSOFT_DATA,
            unique_guid: Guid::random(),
            first_lba: 2048,
            last_lba: total - GPT_FIRST_USABLE_LBA,
            attributes: 0,
            name: "Main Data Partition".into(),
        }],
    };
    gpt.write(&mut dev).unwrap();
    drop(dev);

    let out = Command::new("sgdisk").arg("-v").arg(&img).output().expect("sgdisk is installed");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{text}");
    assert!(text.contains("No problems found"), "{text}");

    let out = Command::new("sfdisk").arg("-J").arg(&img).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["partitiontable"]["label"], "gpt");
    let p = &v["partitiontable"]["partitions"][0];
    assert_eq!(p["start"], 2048);
    assert_eq!(p["name"], "Main Data Partition");
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p rufus-part`
Expected: compile errors (`Guid`, `Gpt` undefined).

- [ ] **Step 3: Implement GUIDs**

`crates/rufus-part/src/guid.rs` (above the tests):
```rust
use std::fmt;

/// A GUID in on-disk (mixed-endian) byte order, as stored in GPT structures.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Guid(pub [u8; 16]);

impl Guid {
    pub const ZERO: Guid = Guid([0; 16]);

    /// Builds a GUID from its textual fields (`d1-d2-d3-d4[0..2]-d4[2..8]`).
    pub const fn from_fields(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> Guid {
        let a = d1.to_le_bytes();
        let b = d2.to_le_bytes();
        let c = d3.to_le_bytes();
        Guid([
            a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d4[0], d4[1], d4[2], d4[3], d4[4],
            d4[5], d4[6], d4[7],
        ])
    }

    /// A random (version 4) GUID, like Windows `CoCreateGuid`.
    pub fn random() -> Guid {
        Guid(uuid::Uuid::new_v4().to_bytes_le())
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.0;
        let d1 = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        let d2 = u16::from_le_bytes([b[4], b[5]]);
        let d3 = u16::from_le_bytes([b[6], b[7]]);
        write!(f, "{d1:08X}-{d2:04X}-{d3:04X}-{:02X}{:02X}-", b[8], b[9])?;
        for x in &b[10..16] {
            write!(f, "{x:02X}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Guid({self})")
    }
}

/// A random 32-bit value (MBR disk signatures).
pub fn random_u32() -> u32 {
    let b = uuid::Uuid::new_v4().into_bytes();
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// Hides a basic data partition from drive-letter assignment on Windows.
pub const GPT_BASIC_DATA_ATTRIBUTE_NO_DRIVE_LETTER: u64 = 0x8000_0000_0000_0000;

/// GPT partition type GUIDs. upstream: gpt_types.h @942ed3a4
pub mod types {
    use super::Guid;

    pub const ESP: Guid = Guid::from_fields(
        0xC12A_7328,
        0xF81F,
        0x11D2,
        [0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B],
    );
    pub const LINUX_DATA: Guid = Guid::from_fields(
        0x0FC6_3DAF,
        0x8483,
        0x4772,
        [0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4],
    );
    pub const MICROSOFT_DATA: Guid = Guid::from_fields(
        0xEBD0_A0A2,
        0xB9E5,
        0x4433,
        [0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7],
    );
    pub const MICROSOFT_RESERVED: Guid = Guid::from_fields(
        0xE3C9_E316,
        0x0B5C,
        0x4DB8,
        [0x81, 0x7D, 0xF9, 0x2D, 0xF0, 0x02, 0x15, 0xAE],
    );
}
```

- [ ] **Step 4: Implement GPT**

`crates/rufus-part/src/gpt.rs` (above the tests):
```rust
use crate::{Guid, Mbr, MbrPartition, PartError};
use rufus_blockdev::BlockDevice;

pub const GPT_ENTRIES: u32 = 128;
pub const GPT_ENTRY_SIZE: u32 = 128;
/// upstream: drive.c CreatePartition @942ed3a4 (StartingUsableOffset = 34 sectors)
pub const GPT_FIRST_USABLE_LBA: u64 = 34;

const SIGNATURE: &[u8; 8] = b"EFI PART";
const REVISION: u32 = 0x0001_0000;
const HEADER_SIZE: u32 = 92;
const NAME_UNITS: usize = 36;

/// One GPT partition entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GptPartition {
    pub type_guid: Guid,
    pub unique_guid: Guid,
    pub first_lba: u64,
    pub last_lba: u64,
    pub attributes: u64,
    pub name: String,
}

/// A GUID partition table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gpt {
    pub disk_guid: Guid,
    pub partitions: Vec<GptPartition>,
}

struct HeaderFields {
    my_lba: u64,
    alternate_lba: u64,
    last_usable: u64,
    entries_lba: u64,
    entries_crc: u32,
}

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

fn le64(b: &[u8]) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[..8]);
    u64::from_le_bytes(a)
}

impl Gpt {
    fn entries_bytes(&self) -> Vec<u8> {
        let size = GPT_ENTRY_SIZE as usize;
        let mut buf = vec![0u8; GPT_ENTRIES as usize * size];
        for (i, p) in self.partitions.iter().enumerate() {
            let e = &mut buf[i * size..(i + 1) * size];
            e[0..16].copy_from_slice(&p.type_guid.0);
            e[16..32].copy_from_slice(&p.unique_guid.0);
            e[32..40].copy_from_slice(&p.first_lba.to_le_bytes());
            e[40..48].copy_from_slice(&p.last_lba.to_le_bytes());
            e[48..56].copy_from_slice(&p.attributes.to_le_bytes());
            for (j, unit) in p.name.encode_utf16().take(NAME_UNITS).enumerate() {
                e[56 + 2 * j..58 + 2 * j].copy_from_slice(&unit.to_le_bytes());
            }
        }
        buf
    }

    fn header(&self, sector_size: u32, f: &HeaderFields) -> Vec<u8> {
        let mut h = vec![0u8; sector_size as usize];
        h[0..8].copy_from_slice(SIGNATURE);
        h[8..12].copy_from_slice(&REVISION.to_le_bytes());
        h[12..16].copy_from_slice(&HEADER_SIZE.to_le_bytes());
        h[24..32].copy_from_slice(&f.my_lba.to_le_bytes());
        h[32..40].copy_from_slice(&f.alternate_lba.to_le_bytes());
        h[40..48].copy_from_slice(&GPT_FIRST_USABLE_LBA.to_le_bytes());
        h[48..56].copy_from_slice(&f.last_usable.to_le_bytes());
        h[56..72].copy_from_slice(&self.disk_guid.0);
        h[72..80].copy_from_slice(&f.entries_lba.to_le_bytes());
        h[80..84].copy_from_slice(&GPT_ENTRIES.to_le_bytes());
        h[84..88].copy_from_slice(&GPT_ENTRY_SIZE.to_le_bytes());
        h[88..92].copy_from_slice(&f.entries_crc.to_le_bytes());
        let crc = crc32fast::hash(&h[..HEADER_SIZE as usize]);
        h[16..20].copy_from_slice(&crc.to_le_bytes());
        h
    }

    /// Writes the protective MBR, the primary GPT and the backup GPT.
    pub fn write(&self, dev: &mut dyn BlockDevice) -> Result<(), PartError> {
        let ss = u64::from(dev.sector_size());
        let total = dev.len() / ss;
        if total < 2 * GPT_FIRST_USABLE_LBA + 1 {
            return Err(PartError::DiskTooSmall);
        }
        if self.partitions.len() > GPT_ENTRIES as usize {
            return Err(PartError::InvalidRequest("too many GPT partitions"));
        }
        let last_usable = total - GPT_FIRST_USABLE_LBA;
        for p in &self.partitions {
            if p.first_lba < GPT_FIRST_USABLE_LBA || p.last_lba > last_usable || p.first_lba > p.last_lba {
                return Err(PartError::InvalidRequest("GPT partition outside the usable area"));
            }
        }
        let entries = self.entries_bytes();
        let entries_sectors = (entries.len() as u64).div_ceil(ss);
        let entries_crc = crc32fast::hash(&entries);
        let backup_lba = total - 1;
        let backup_entries_lba = backup_lba - entries_sectors;
        let primary = self.header(
            ss as u32,
            &HeaderFields { my_lba: 1, alternate_lba: backup_lba, last_usable, entries_lba: 2, entries_crc },
        );
        let backup = self.header(
            ss as u32,
            &HeaderFields {
                my_lba: backup_lba,
                alternate_lba: 1,
                last_usable,
                entries_lba: backup_entries_lba,
                entries_crc,
            },
        );
        let pmbr = Mbr {
            disk_signature: 0,
            partitions: [
                Some(MbrPartition {
                    bootable: false,
                    part_type: 0xEE,
                    start_lba: 1,
                    sectors: (total - 1).min(u64::from(u32::MAX)) as u32,
                }),
                None,
                None,
                None,
            ],
        };
        let mut pmbr_sector = pmbr.to_sector(ss as u32);
        // UEFI spec: the protective partition's ending CHS is 0xFFFFFF.
        pmbr_sector[0x1BE + 5..0x1BE + 8].copy_from_slice(&[0xFF, 0xFF, 0xFF]);

        dev.write_at(0, &pmbr_sector)?;
        dev.write_at(2 * ss, &entries)?;
        dev.write_at(ss, &primary)?;
        dev.write_at(backup_entries_lba * ss, &entries)?;
        dev.write_at(backup_lba * ss, &backup)?;
        Ok(())
    }

    /// Reads and validates the primary GPT.
    pub fn read(dev: &mut dyn BlockDevice) -> Result<Gpt, PartError> {
        let ss = dev.sector_size() as usize;
        let mut h = vec![0u8; ss];
        dev.read_at(ss as u64, &mut h)?;
        if &h[0..8] != SIGNATURE {
            return Err(PartError::NoGpt);
        }
        let header_size = le32(&h[12..16]) as usize;
        if header_size < HEADER_SIZE as usize || header_size > ss {
            return Err(PartError::NoGpt);
        }
        let stored_crc = le32(&h[16..20]);
        let mut tmp = h[..header_size].to_vec();
        tmp[16..20].fill(0);
        if crc32fast::hash(&tmp) != stored_crc {
            return Err(PartError::GptHeaderCrc);
        }
        let entries_lba = le64(&h[72..80]);
        let count = le32(&h[80..84]) as usize;
        let entry_size = le32(&h[84..88]) as usize;
        if count == 0 || count > 1024 || !(128..=4096).contains(&entry_size) || entry_size % 8 != 0 {
            return Err(PartError::NoGpt);
        }
        let mut entries = vec![0u8; count * entry_size];
        let offset = entries_lba.checked_mul(ss as u64).ok_or(PartError::NoGpt)?;
        dev.read_at(offset, &mut entries)?;
        if crc32fast::hash(&entries) != le32(&h[88..92]) {
            return Err(PartError::GptEntriesCrc);
        }
        let mut disk_guid = [0u8; 16];
        disk_guid.copy_from_slice(&h[56..72]);
        let mut partitions = Vec::new();
        for e in entries.chunks_exact(entry_size) {
            let mut type_guid = [0u8; 16];
            type_guid.copy_from_slice(&e[0..16]);
            if type_guid == [0u8; 16] {
                continue;
            }
            let mut unique = [0u8; 16];
            unique.copy_from_slice(&e[16..32]);
            let units: Vec<u16> = e[56..128]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .take_while(|&u| u != 0)
                .collect();
            partitions.push(GptPartition {
                type_guid: Guid(type_guid),
                unique_guid: Guid(unique),
                first_lba: le64(&e[32..40]),
                last_lba: le64(&e[40..48]),
                attributes: le64(&e[48..56]),
                name: String::from_utf16_lossy(&units),
            });
        }
        Ok(Gpt { disk_guid: Guid(disk_guid), partitions })
    }
}
```

`crates/rufus-part/src/lib.rs`:
```rust
//! MBR and GPT partition tables, and Rufus's partition layout planner.

mod error;
mod gpt;
mod guid;
mod mbr;

pub use error::PartError;
pub use gpt::{GPT_ENTRIES, GPT_ENTRY_SIZE, GPT_FIRST_USABLE_LBA, Gpt, GptPartition};
pub use guid::{GPT_BASIC_DATA_ATTRIBUTE_NO_DRIVE_LETTER, Guid, random_u32, types};
pub use mbr::{MBR_UEFI_MARKER, Mbr, MbrPartition, lba_to_chs};
```

- [ ] **Step 5: Run the tests**

Run: `cargo test -p rufus-part`
Expected: all unit tests pass, and `sgdisk_and_sfdisk_accept_our_gpt` passes.

- [ ] **Step 6: Commit**

```bash
git add crates/rufus-part
git commit -m "feat(part): GPT read/write with protective MBR and backup header"
```

---

### Task 4: `rufus-part` — Rufus layout planner (`CreatePartition` port)

**Files:**
- Create: `crates/rufus-part/src/layout.rs`
- Modify: `crates/rufus-part/src/lib.rs`
- Test: `crates/rufus-part/tests/layout.rs`, `crates/rufus-part/tests/sfdisk_layout.rs`

**Interfaces:**
- Consumes: `Mbr`, `MbrPartition`, `Gpt`, `GptPartition`, `Guid`, `types`, `random_u32`, `GPT_BASIC_DATA_ATTRIBUTE_NO_DRIVE_LETTER`, `MBR_UEFI_MARKER` (Tasks 2–3).
- Produces:
  - `pub struct Geometry { pub disk_size: u64, pub sector_size: u32, pub sectors_per_track: u32 }`, `Geometry::new(disk_size, sector_size)` (63 sectors/track)
  - `pub enum PartitionStyle { Mbr, Gpt, SuperFloppy }`
  - `pub enum MainFs { Fat16, Fat32, Ntfs, Exfat, Udf, Refs, Ext2, Ext3, Ext4 }`
  - `pub enum Role { Esp, Msr, Main, Persistence, UefiNtfs, Compat }`
  - `pub struct ExtraPartitions { pub msr: bool, pub esp: bool, pub uefi_ntfs: bool, pub compat: bool, pub persistence: bool }` (Default)
  - `pub struct LayoutRequest { pub geometry: Geometry, pub style: PartitionStyle, pub main_fs: MainFs, pub cluster_size: u64, pub extra: ExtraPartitions, pub old_bios_fixes: bool, pub write_as_esp: bool, pub bootable: bool, pub persistence_size: u64, pub uefi_ntfs_size: u64 }`
  - `pub struct PlannedPartition { pub role: Role, pub name: &'static str, pub offset: u64, pub size: u64 }`
  - `pub struct Layout { pub style: PartitionStyle, pub partitions: Vec<PlannedPartition>, pub main_index: usize, pub bootable: bool, pub main_fs: MainFs }` with `main(&self) -> &PlannedPartition`, `to_mbr(&self, sector_size: u32, disk_signature: u32) -> Result<Mbr, PartError>`, `to_gpt(&self, sector_size: u32, disk_guid: Guid, partition_guids: &[Guid]) -> Result<Gpt, PartError>`
  - `pub struct DiskIds { pub mbr_signature: u32, pub gpt_disk_guid: Guid, pub gpt_partition_guids: Vec<Guid> }`, `DiskIds::random(partition_count: usize, mbr_uefi_marker: bool)`
  - `pub fn plan_layout(&LayoutRequest) -> Result<Layout, PartError>`
  - `pub fn apply_layout(&mut dyn BlockDevice, &Layout, &DiskIds) -> Result<(), PartError>`
  - Constants `MB`, `GB`, `ESP_SIZE`, `MSR_SIZE`, `MAX_ISO_TO_ESP_SIZE`, `MAX_SECTORS_TO_CLEAR`, `MAX_PARTITIONS`, `RUFUS_EXTRA_PARTITION_TYPE`, `DEFAULT_SECTORS_PER_TRACK`, and names `NAME_ESP`, `NAME_MSR`, `NAME_MAIN`, `NAME_PERSISTENCE`, `NAME_UEFI_NTFS`, `NAME_COMPAT`.

Parity notes for the implementer:
- Upstream puts the ESP first only when `MediaType == FixedMedia || Windows build > 15000`. Every OS we target satisfies the "can mount more than one partition" condition, so the ESP-first branch always applies. As in upstream, the ESP and MSR extras are only valid with GPT.
- Upstream reads `SectorsPerTrack` from Windows, which reports 63 for USB drives. `Geometry::new` defaults to 63. Platform backends may override it.
- The expected numbers in the tests below come from a line-by-line replica of upstream's arithmetic.

- [ ] **Step 1: Write the failing tests**

`crates/rufus-part/tests/layout.rs`:
```rust
use proptest::prelude::*;
use rufus_blockdev::MemDevice;
use rufus_part::*;

const MIB: u64 = 1 << 20;
const GIB: u64 = 1 << 30;

fn req(disk: u64, ss: u32, style: PartitionStyle, cluster: u64) -> LayoutRequest {
    LayoutRequest {
        geometry: Geometry::new(disk, ss),
        style,
        main_fs: MainFs::Fat32,
        cluster_size: cluster,
        extra: ExtraPartitions::default(),
        old_bios_fixes: false,
        write_as_esp: false,
        bootable: true,
        persistence_size: 0,
        uefi_ntfs_size: 0,
    }
}

fn spans(l: &Layout) -> Vec<(Role, u64, u64)> {
    l.partitions.iter().map(|p| (p.role, p.offset, p.size)).collect()
}

#[test]
fn mbr_8gib_single_partition() {
    let l = plan_layout(&req(8 * GIB, 512, PartitionStyle::Mbr, 4096)).unwrap();
    assert_eq!(spans(&l), vec![(Role::Main, MIB, 8_588_869_632)]);
    assert_eq!(l.main().name, NAME_MAIN);
}

#[test]
fn gpt_16gib_with_esp_first() {
    let mut r = req(16 * GIB, 512, PartitionStyle::Gpt, 4096);
    r.extra.esp = true;
    let l = plan_layout(&r).unwrap();
    assert_eq!(
        spans(&l),
        vec![(Role::Esp, MIB, 272_629_760), (Role::Main, 273_690_624, 16_906_141_696)]
    );
    assert_eq!(l.main_index, 1);
}

#[test]
fn mbr_16gib_with_persistence() {
    let mut r = req(16 * GIB, 512, PartitionStyle::Mbr, 4096);
    r.extra.persistence = true;
    r.persistence_size = 4 * GIB;
    let l = plan_layout(&r).unwrap();
    assert_eq!(
        spans(&l),
        vec![
            (Role::Main, MIB, 12_883_820_544),
            (Role::Persistence, 12_884_884_992, 4_294_983_168)
        ]
    );
    let mbr = l.to_mbr(512, 1).unwrap();
    let p0 = mbr.partitions[0].unwrap();
    let p1 = mbr.partitions[1].unwrap();
    assert_eq!((p0.part_type, p0.bootable), (0x0c, true));
    assert_eq!((p1.part_type, p1.bootable), (0x83, false));
}

#[test]
fn mbr_old_bios_fixes_offset() {
    let mut r = req(8 * GIB, 512, PartitionStyle::Mbr, 4096);
    r.old_bios_fixes = true;
    let l = plan_layout(&r).unwrap();
    assert_eq!(spans(&l), vec![(Role::Main, 65_536, 8_589_836_288)]);
}

#[test]
fn gpt_4k_layout() {
    let l = plan_layout(&req(8 * GIB + 12_345 * 4096, 4096, PartitionStyle::Gpt, 4096)).unwrap();
    assert_eq!(spans(&l), vec![(Role::Main, MIB, 8_639_188_992)]);
}

#[test]
fn mbr_uefi_ntfs_odd_disk_size() {
    let mut r = req(7_999_999_488, 512, PartitionStyle::Mbr, 32_768);
    r.main_fs = MainFs::Ntfs;
    r.extra.uefi_ntfs = true;
    r.uefi_ntfs_size = MIB;
    let l = plan_layout(&r).unwrap();
    assert_eq!(
        spans(&l),
        vec![(Role::Main, MIB, 7_997_816_832), (Role::UefiNtfs, 7_998_907_392, 1_064_448)]
    );
    let mbr = l.to_mbr(512, 1).unwrap();
    assert_eq!(mbr.partitions[0].unwrap().part_type, 0x07);
    assert_eq!(mbr.partitions[1].unwrap().part_type, 0xef);
}

#[test]
fn write_as_esp_caps_main_at_1gib() {
    let mut r = req(8 * GIB, 512, PartitionStyle::Mbr, 4096);
    r.write_as_esp = true;
    let l = plan_layout(&r).unwrap();
    assert_eq!(spans(&l), vec![(Role::Main, MIB, 1_073_737_728)]);
    assert_eq!(l.main().name, NAME_ESP);
    assert_eq!(l.to_mbr(512, 1).unwrap().partitions[0].unwrap().part_type, 0xef);
}

#[test]
fn compat_partition_with_default_cluster() {
    let mut r = req(8 * GIB, 512, PartitionStyle::Mbr, 0);
    r.extra.compat = true;
    let l = plan_layout(&r).unwrap();
    assert_eq!(
        spans(&l),
        vec![(Role::Main, MIB, 8_588_837_376), (Role::Compat, 8_589_901_824, 32_256)]
    );
    assert_eq!(l.to_mbr(512, 1).unwrap().partitions[1].unwrap().part_type, RUFUS_EXTRA_PARTITION_TYPE);
}

#[test]
fn gpt_types_and_attributes() {
    let mut r = req(16 * GIB, 512, PartitionStyle::Gpt, 4096);
    r.extra.esp = true;
    let l = plan_layout(&r).unwrap();
    let gpt = l.to_gpt(512, Guid::random(), &[Guid::random(), Guid::random()]).unwrap();
    assert_eq!(gpt.partitions[0].type_guid, types::ESP);
    assert_eq!(gpt.partitions[0].name, "EFI System Partition");
    assert_eq!(gpt.partitions[1].type_guid, types::MICROSOFT_DATA);
    assert_eq!(gpt.partitions[1].first_lba, 273_690_624 / 512);

    let mut r = req(8 * GIB, 512, PartitionStyle::Gpt, 4096);
    r.extra.uefi_ntfs = true;
    r.uefi_ntfs_size = MIB;
    let l = plan_layout(&r).unwrap();
    let gpt = l.to_gpt(512, Guid::random(), &[Guid::random(), Guid::random()]).unwrap();
    assert_eq!(gpt.partitions[1].type_guid, types::MICROSOFT_DATA);
    assert_eq!(gpt.partitions[1].attributes, GPT_BASIC_DATA_ATTRIBUTE_NO_DRIVE_LETTER);
}

#[test]
fn invalid_requests() {
    let mut r = req(8 * GIB, 512, PartitionStyle::Mbr, 4096);
    r.extra.esp = true;
    assert!(matches!(plan_layout(&r), Err(PartError::InvalidRequest(_))));

    let mut r = req(8 * GIB, 512, PartitionStyle::Mbr, 4096);
    r.extra.persistence = true;
    assert!(matches!(plan_layout(&r), Err(PartError::InvalidRequest(_))));

    assert!(matches!(
        plan_layout(&req(MIB, 512, PartitionStyle::Mbr, 4096)),
        Err(PartError::DiskTooSmall)
    ));
}

#[test]
fn superfloppy_uses_whole_disk() {
    let l = plan_layout(&req(8 * GIB, 512, PartitionStyle::SuperFloppy, 4096)).unwrap();
    assert_eq!(spans(&l), vec![(Role::Main, 0, 8 * GIB)]);
}

#[test]
fn apply_mbr_clears_and_writes_table() {
    let len = 64 * MIB;
    let mut dev = MemDevice::from_vec(vec![0xFF; len as usize], 512);
    let l = plan_layout(&req(len, 512, PartitionStyle::Mbr, 4096)).unwrap();
    apply_layout(&mut dev, &l, &DiskIds::random(l.partitions.len(), true)).unwrap();

    let mbr = Mbr::read(&mut dev).unwrap();
    assert_eq!(mbr.disk_signature, MBR_UEFI_MARKER);
    let p = mbr.partitions[0].unwrap();
    assert_eq!(u64::from(p.start_lba) * 512, l.main().offset);
    assert_eq!(u64::from(p.sectors) * 512, l.main().size);

    let off = l.main().offset as usize;
    let clear = (MAX_SECTORS_TO_CLEAR * 512) as usize;
    let bytes = dev.as_bytes();
    assert!(bytes[off..off + clear].iter().all(|&b| b == 0));
    assert_eq!(bytes[off + clear], 0xFF);
}

#[test]
fn apply_gpt_4k() {
    let len = 64 * MIB;
    let mut dev = MemDevice::new(len as usize, 4096);
    let l = plan_layout(&req(len, 4096, PartitionStyle::Gpt, 4096)).unwrap();
    apply_layout(&mut dev, &l, &DiskIds::random(l.partitions.len(), false)).unwrap();
    let gpt = Gpt::read(&mut dev).unwrap();
    assert_eq!(gpt.partitions.len(), 1);
    assert_eq!(gpt.partitions[0].first_lba * 4096, l.main().offset);
    assert_eq!((gpt.partitions[0].last_lba + 1) * 4096, l.main().offset + l.main().size);
    // the backup GPT header sits in the very last 4 KiB sector
    assert_eq!(&dev.as_bytes()[(len - 4096) as usize..(len - 4096) as usize + 8], b"EFI PART");
}

proptest! {
    #[test]
    fn layout_invariants(
        disk in (64 * MIB)..(64 * GIB),
        gpt in any::<bool>(),
        four_k in any::<bool>(),
        cluster_pow in 9u32..17,
        persistence in any::<bool>(),
        compat in any::<bool>(),
    ) {
        let ss = if four_k { 4096 } else { 512 };
        let style = if gpt { PartitionStyle::Gpt } else { PartitionStyle::Mbr };
        let mut r = req(disk, ss, style, 1u64 << cluster_pow);
        r.extra.persistence = persistence;
        r.persistence_size = 16 * MIB;
        r.extra.compat = compat;
        let l = plan_layout(&r).unwrap();
        let end_limit = disk - if gpt { 33 * u64::from(ss) } else { 0 };
        let mut prev_end = 0;
        for p in &l.partitions {
            prop_assert!(p.size > 0);
            prop_assert_eq!(p.offset % u64::from(ss), 0);
            prop_assert_eq!(p.size % u64::from(ss), 0);
            prop_assert!(p.offset >= prev_end);
            prev_end = p.offset + p.size;
        }
        prop_assert!(prev_end <= end_limit);
    }
}
```

`crates/rufus-part/tests/sfdisk_layout.rs`:
```rust
#![cfg(target_os = "linux")]

use rufus_blockdev::FileDevice;
use rufus_part::*;
use std::process::Command;

#[test]
fn sfdisk_sees_planned_gpt_layout() {
    let dir = tempfile::tempdir().unwrap();
    let img = dir.path().join("layout.img");
    let len: u64 = 1 << 30;
    let mut dev = FileDevice::create(&img, len, 512).unwrap();
    let r = LayoutRequest {
        geometry: Geometry::new(len, 512),
        style: PartitionStyle::Gpt,
        main_fs: MainFs::Fat32,
        cluster_size: 4096,
        extra: ExtraPartitions { esp: true, ..Default::default() },
        old_bios_fixes: false,
        write_as_esp: false,
        bootable: false,
        persistence_size: 0,
        uefi_ntfs_size: 0,
    };
    let l = plan_layout(&r).unwrap();
    apply_layout(&mut dev, &l, &DiskIds::random(l.partitions.len(), false)).unwrap();
    drop(dev);

    let out = Command::new("sfdisk").arg("-J").arg(&img).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let parts = v["partitiontable"]["partitions"].as_array().unwrap();
    assert_eq!(parts.len(), 2);
    assert_eq!(parts[0]["start"], 2048);
    assert_eq!(parts[0]["type"], "C12A7328-F81F-11D2-BA4B-00A0C93EC93B");
    assert_eq!(parts[1]["start"], l.main().offset / 512);

    let out = Command::new("sgdisk").arg("-v").arg(&img).output().unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains("No problems found"));
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p rufus-part --test layout`
Expected: compile errors (`plan_layout`, `LayoutRequest` undefined).

- [ ] **Step 3: Implement the planner**

`crates/rufus-part/src/layout.rs`:
```rust
use crate::{
    GPT_BASIC_DATA_ATTRIBUTE_NO_DRIVE_LETTER, Gpt, GptPartition, Guid, MBR_UEFI_MARKER, Mbr,
    MbrPartition, PartError, random_u32, types,
};
use rufus_blockdev::BlockDevice;

pub const MB: u64 = 1 << 20;
pub const GB: u64 = 1 << 30;
/// upstream: drive.c CreatePartition @942ed3a4 — "260 MB sized ESP ... to keep everyone happy"
pub const ESP_SIZE: u64 = 260 * MB;
pub const MSR_SIZE: u64 = 128 * MB;
/// upstream: rufus.h MAX_ISO_TO_ESP_SIZE @942ed3a4
pub const MAX_ISO_TO_ESP_SIZE: u64 = GB;
/// upstream: rufus.h MAX_SECTORS_TO_CLEAR @942ed3a4 (a sector count, scaled by the sector size)
pub const MAX_SECTORS_TO_CLEAR: u64 = 8 * MB / 512;
/// upstream: rufus.h MAX_PARTITIONS @942ed3a4
pub const MAX_PARTITIONS: usize = 16;
/// upstream: drive.h RUFUS_EXTRA_PARTITION_TYPE @942ed3a4
pub const RUFUS_EXTRA_PARTITION_TYPE: u8 = 0xEA;
pub const DEFAULT_SECTORS_PER_TRACK: u32 = 63;

pub const NAME_ESP: &str = "EFI System Partition";
pub const NAME_MSR: &str = "Microsoft Reserved Partition";
pub const NAME_MAIN: &str = "Main Data Partition";
pub const NAME_PERSISTENCE: &str = "Linux Persistence";
pub const NAME_UEFI_NTFS: &str = "UEFI:NTFS";
pub const NAME_COMPAT: &str = "BIOS Compatibility";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Geometry {
    pub disk_size: u64,
    pub sector_size: u32,
    pub sectors_per_track: u32,
}

impl Geometry {
    pub fn new(disk_size: u64, sector_size: u32) -> Self {
        Self { disk_size, sector_size, sectors_per_track: DEFAULT_SECTORS_PER_TRACK }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionStyle {
    Mbr,
    Gpt,
    /// No partition table; the file system spans the whole device.
    SuperFloppy,
}

/// File system of the main partition (it decides the MBR partition type).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MainFs {
    Fat16,
    Fat32,
    Ntfs,
    Exfat,
    Udf,
    Refs,
    Ext2,
    Ext3,
    Ext4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Esp,
    Msr,
    Main,
    Persistence,
    UefiNtfs,
    Compat,
}

/// upstream: drive.h XP_* flags @942ed3a4
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExtraPartitions {
    pub msr: bool,
    pub esp: bool,
    pub uefi_ntfs: bool,
    pub compat: bool,
    pub persistence: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutRequest {
    pub geometry: Geometry,
    pub style: PartitionStyle,
    pub main_fs: MainFs,
    /// Cluster size chosen in the UI; 0 means "default" (treated as 512 here, like upstream).
    pub cluster_size: u64,
    pub extra: ExtraPartitions,
    pub old_bios_fixes: bool,
    pub write_as_esp: bool,
    /// Whether the main MBR partition gets the active flag (boot type != non-bootable).
    pub bootable: bool,
    pub persistence_size: u64,
    pub uefi_ntfs_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedPartition {
    pub role: Role,
    pub name: &'static str,
    pub offset: u64,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    pub style: PartitionStyle,
    pub partitions: Vec<PlannedPartition>,
    pub main_index: usize,
    pub bootable: bool,
    pub main_fs: MainFs,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskIds {
    pub mbr_signature: u32,
    pub gpt_disk_guid: Guid,
    pub gpt_partition_guids: Vec<Guid>,
}

impl DiskIds {
    /// Fresh identifiers. With `mbr_uefi_marker`, the MBR signature is the
    /// Rufus "UEFI" marker instead of a random value.
    pub fn random(partition_count: usize, mbr_uefi_marker: bool) -> DiskIds {
        DiskIds {
            mbr_signature: if mbr_uefi_marker { MBR_UEFI_MARKER } else { random_u32() },
            gpt_disk_guid: Guid::random(),
            gpt_partition_guids: (0..partition_count).map(|_| Guid::random()).collect(),
        }
    }
}

fn floor_align(x: u64, y: u64) -> u64 {
    x / y * y
}

fn ceiling_align(x: u64, y: u64) -> u64 {
    x.div_ceil(y) * y
}

fn part(role: Role, name: &'static str, offset: u64, size: u64) -> PlannedPartition {
    PlannedPartition { role, name, offset, size }
}

/// Computes partition offsets and sizes exactly like upstream.
/// upstream: drive.c CreatePartition @942ed3a4
pub fn plan_layout(req: &LayoutRequest) -> Result<Layout, PartError> {
    let g = req.geometry;
    let ss = u64::from(g.sector_size);
    let bytes_per_track = u64::from(g.sectors_per_track) * ss;
    let cluster = if req.cluster_size == 0 { 0x200 } else { req.cluster_size };
    let mut extra = req.extra;
    let main_name = if req.write_as_esp { NAME_ESP } else { NAME_MAIN };
    let layout = |partitions, main_index| Layout {
        style: req.style,
        partitions,
        main_index,
        bootable: req.bootable,
        main_fs: req.main_fs,
    };

    if req.style == PartitionStyle::SuperFloppy {
        return Ok(layout(vec![part(Role::Main, main_name, 0, g.disk_size)], 0));
    }
    if (extra.esp || extra.msr) && req.style != PartitionStyle::Gpt {
        return Err(PartError::InvalidRequest("ESP/MSR extra partitions require GPT"));
    }

    let align_next = |end: u64| {
        let next = ceiling_align(end, bytes_per_track);
        if cluster % ss == 0 { floor_align(next, cluster) } else { next }
    };

    let mut partitions = Vec::new();
    let mut offset = if req.style == PartitionStyle::Gpt || !req.old_bios_fixes {
        MB
    } else {
        // Align to a cylinder that is itself aligned to the cluster size, then
        // double it so that GRUB2 fits.
        ceiling_align(bytes_per_track, cluster) * 2
    };

    if extra.esp {
        partitions.push(part(Role::Esp, NAME_ESP, offset, ESP_SIZE));
        offset = align_next(offset + ESP_SIZE);
        extra.esp = false;
    }
    if extra.msr {
        partitions.push(part(Role::Msr, NAME_MSR, offset, MSR_SIZE));
        offset = align_next(offset + MSR_SIZE);
        extra.msr = false;
    }

    let main_index = partitions.len();
    partitions.push(part(Role::Main, main_name, offset, 0));

    if extra.persistence {
        if req.persistence_size == 0 {
            return Err(PartError::InvalidRequest("persistence requested with a size of 0"));
        }
        partitions.push(part(
            Role::Persistence,
            NAME_PERSISTENCE,
            0,
            ceiling_align(req.persistence_size, bytes_per_track),
        ));
    }
    if extra.esp {
        partitions.push(part(Role::Esp, NAME_ESP, 0, ceiling_align(ESP_SIZE, bytes_per_track)));
    } else if extra.uefi_ntfs {
        if req.uefi_ntfs_size == 0 {
            return Err(PartError::InvalidRequest("UEFI:NTFS requested without an image size"));
        }
        partitions.push(part(
            Role::UefiNtfs,
            NAME_UEFI_NTFS,
            0,
            ceiling_align(req.uefi_ntfs_size, bytes_per_track),
        ));
    } else if extra.compat {
        partitions.push(part(Role::Compat, NAME_COMPAT, 0, bytes_per_track));
    }
    if partitions.len() > MAX_PARTITIONS {
        return Err(PartError::InvalidRequest("too many partitions"));
    }

    let reserved_end = if req.style == PartitionStyle::Gpt { 33 * ss } else { 0 };
    let mut last = g.disk_size.checked_sub(reserved_end).ok_or(PartError::DiskTooSmall)?;
    for p in partitions.iter_mut().skip(main_index + 1).rev() {
        if p.size >= last {
            return Err(PartError::DiskTooSmall);
        }
        p.offset = floor_align(last - p.size, bytes_per_track);
        last = p.offset;
    }

    let main_offset = partitions[main_index].offset;
    let mut main_size = last.checked_sub(main_offset).ok_or(PartError::DiskTooSmall)?;
    if req.write_as_esp {
        main_size = main_size.min(MAX_ISO_TO_ESP_SIZE);
    }
    let mut size = floor_align(main_size, bytes_per_track);
    if cluster % ss == 0 {
        size = floor_align(size, cluster);
    }
    if size == 0 {
        return Err(PartError::DiskTooSmall);
    }
    partitions[main_index].size = size;
    Ok(layout(partitions, main_index))
}

impl Layout {
    pub fn main(&self) -> &PlannedPartition {
        &self.partitions[self.main_index]
    }

    fn mbr_type(&self, index: usize) -> u8 {
        let p = &self.partitions[index];
        let main_type = match self.main_fs {
            MainFs::Fat16 => 0x0e,
            MainFs::Ntfs | MainFs::Exfat | MainFs::Udf | MainFs::Refs => 0x07,
            MainFs::Ext2 | MainFs::Ext3 | MainFs::Ext4 => 0x83,
            MainFs::Fat32 => 0x0c,
        };
        match p.name {
            NAME_ESP | NAME_UEFI_NTFS => 0xef,
            NAME_PERSISTENCE => 0x83,
            NAME_COMPAT => RUFUS_EXTRA_PARTITION_TYPE,
            _ if index == self.main_index => main_type,
            _ => 0,
        }
    }

    /// The MBR table for this layout.
    pub fn to_mbr(&self, sector_size: u32, disk_signature: u32) -> Result<Mbr, PartError> {
        if self.partitions.len() > 4 {
            return Err(PartError::InvalidRequest("MBR supports at most 4 partitions"));
        }
        let ss = u64::from(sector_size);
        let mut mbr = Mbr { disk_signature, partitions: [None; 4] };
        for (i, p) in self.partitions.iter().enumerate() {
            let start = p.offset / ss;
            let sectors = p.size / ss;
            if start > u64::from(u32::MAX) || sectors > u64::from(u32::MAX) {
                return Err(PartError::MbrOverflow(i));
            }
            mbr.partitions[i] = Some(MbrPartition {
                bootable: i == self.main_index && self.bootable,
                part_type: self.mbr_type(i),
                start_lba: start as u32,
                sectors: sectors as u32,
            });
        }
        Ok(mbr)
    }

    /// The GPT for this layout.
    pub fn to_gpt(&self, sector_size: u32, disk_guid: Guid, partition_guids: &[Guid]) -> Result<Gpt, PartError> {
        if partition_guids.len() < self.partitions.len() {
            return Err(PartError::InvalidRequest("not enough partition GUIDs"));
        }
        let ss = u64::from(sector_size);
        let partitions = self
            .partitions
            .iter()
            .zip(partition_guids)
            .map(|(p, guid)| {
                let (type_guid, attributes) = match p.name {
                    // A second ESP breaks the Windows installer, so UEFI:NTFS is basic data.
                    NAME_UEFI_NTFS => (types::MICROSOFT_DATA, GPT_BASIC_DATA_ATTRIBUTE_NO_DRIVE_LETTER),
                    NAME_ESP => (types::ESP, 0),
                    NAME_PERSISTENCE => (types::LINUX_DATA, 0),
                    NAME_MSR => (types::MICROSOFT_RESERVED, 0),
                    _ => (types::MICROSOFT_DATA, 0),
                };
                GptPartition {
                    type_guid,
                    unique_guid: *guid,
                    first_lba: p.offset / ss,
                    last_lba: (p.offset + p.size) / ss - 1,
                    attributes,
                    name: p.name.to_string(),
                }
            })
            .collect();
        Ok(Gpt { disk_guid, partitions })
    }
}

/// Zeroes the start of every planned partition and writes the partition table.
/// upstream: drive.c CreatePartition + ClearPartition @942ed3a4
pub fn apply_layout(dev: &mut dyn BlockDevice, layout: &Layout, ids: &DiskIds) -> Result<(), PartError> {
    if layout.style == PartitionStyle::SuperFloppy {
        return Ok(());
    }
    let ss = dev.sector_size();
    let clear = MAX_SECTORS_TO_CLEAR * u64::from(ss);
    for p in &layout.partitions {
        dev.write_zeros(p.offset, clear.min(p.size))?;
    }
    match layout.style {
        PartitionStyle::Mbr => layout.to_mbr(ss, ids.mbr_signature)?.write(dev)?,
        PartitionStyle::Gpt => layout
            .to_gpt(ss, ids.gpt_disk_guid, &ids.gpt_partition_guids)?
            .write(dev)?,
        PartitionStyle::SuperFloppy => {}
    }
    dev.flush()?;
    Ok(())
}
```

Append to `crates/rufus-part/src/lib.rs`:
```rust
mod layout;

pub use layout::{
    DEFAULT_SECTORS_PER_TRACK, DiskIds, ESP_SIZE, ExtraPartitions, GB, Geometry, Layout,
    LayoutRequest, MAX_ISO_TO_ESP_SIZE, MAX_PARTITIONS, MAX_SECTORS_TO_CLEAR, MB, MSR_SIZE,
    MainFs, NAME_COMPAT, NAME_ESP, NAME_MAIN, NAME_MSR, NAME_PERSISTENCE, NAME_UEFI_NTFS,
    PartitionStyle, PlannedPartition, RUFUS_EXTRA_PARTITION_TYPE, Role, apply_layout, plan_layout,
};
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p rufus-part`
Expected: every test in `tests/layout.rs` (including the proptest) and `tests/sfdisk_layout.rs` passes.

- [ ] **Step 5: Commit**

```bash
git add crates/rufus-part
git commit -m "feat(part): port upstream CreatePartition layout planner"
```

---

### Task 5: `rufus-fat` — time helpers and the FAT32 formatter (`FormatLargeFAT32` port)

**Files:**
- Create: `crates/rufus-fat/Cargo.toml`, `crates/rufus-fat/src/{lib.rs,error.rs,time.rs,label.rs,fat32.rs}`
- Modify: `Cargo.toml` (members, workspace deps)
- Test: unit tests in `time.rs`, `label.rs`, `fat32.rs`; `crates/rufus-fat/tests/fat32_tools.rs`

**Interfaces:**
- Consumes: `BlockDevice`, `MemDevice`, `FileDevice` (Task 1).
- Produces:
  - `pub struct LocalTime { pub year: u16, pub month: u8, pub day: u8, pub hour: u8, pub minute: u8, pub second: u8, pub millisecond: u16 }` with `LocalTime::from_unix(secs: i64, millisecond: u16) -> LocalTime` (UTC calendar) and `dos_time_date(&self) -> (u16, u16)`
  - `pub fn volume_id(&LocalTime) -> u32`
  - `pub fn label_bytes(&str) -> Result<[u8; 11], FatError>`
  - `pub struct FatOptions { pub cluster_size: u32, pub label: String, pub volume_id: u32, pub hidden_sectors: u32, pub sectors_per_track: u16, pub heads: u16, pub time: LocalTime }`, `FatOptions::new(label: &str, time: LocalTime)`
  - `pub struct FatSummary { pub bytes_per_sector: u32, pub sectors_per_cluster: u32, pub reserved_sectors: u32, pub num_fats: u32, pub fat_sectors: u32, pub root_dir_sectors: u32, pub total_sectors: u64, pub cluster_count: u64 }`
  - `pub fn default_fat32_cluster_size(partition_len: u64) -> u32`
  - `pub fn fat32_geometry(partition_len: u64, bytes_per_sector: u32, cluster_size: u32) -> Result<FatSummary, FatError>`
  - `pub fn format_fat32(&mut dyn BlockDevice, &FatOptions) -> Result<FatSummary, FatError>`
  - `pub enum FatError { Io, TooSmall, TooLarge, InvalidClusterSize(u32), InvalidSectorSize(u32), TooManyClusters(u64), TooFewClusters(u64), InvalidLabel(String) }`

Parity notes for the implementer:
- This is upstream's large-FAT32 formatter. Upstream uses it only for FAT32 over 32 GB (or when forced) and uses Windows `FormatEx` below that. Spec D3 says we use our own formatter for every size, so FAT32 under 32 GB can differ from Windows near cluster-count limits. That divergence is logged in `docs/parity.md` (Task 16) and must not be "fixed" here.
- Upstream calls `GetFATSizeSectors` with `wRsvdSecCnt` **before** assigning it, so it passes a reserved count of 0. Reproduce this exactly; the comment in the code must say so.
- Windows sets the label with `SetVolumeLabel` after formatting, which writes a volume-label entry into the root directory. We write the label into both the BPB and a root-directory entry. An empty label leaves `NO NAME    ` in the BPB and no directory entry.
- The geometry values used by the tests come from a replica of upstream's arithmetic.

- [ ] **Step 1: Create the crate**

Root `Cargo.toml`: add `"crates/rufus-fat"` to `members` and `rufus-fat = { path = "crates/rufus-fat" }` to `[workspace.dependencies]`.

`crates/rufus-fat/Cargo.toml`:
```toml
[package]
name = "rufus-fat"
description = "FAT16/FAT32 formatters ported from Rufus"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true

[dependencies]
rufus-blockdev.workspace = true
thiserror.workspace = true

[dev-dependencies]
tempfile.workspace = true

[lints]
workspace = true
```

`crates/rufus-fat/src/error.rs`:
```rust
use std::io;

/// Errors from the FAT formatters.
#[derive(Debug, thiserror::Error)]
pub enum FatError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("the volume is too small for this file system")]
    TooSmall,
    #[error("the volume is too large for this file system")]
    TooLarge,
    #[error("invalid cluster size {0}")]
    InvalidClusterSize(u32),
    #[error("invalid sector size {0}")]
    InvalidSectorSize(u32),
    #[error("{0} clusters is too many for this file system, use a larger cluster size")]
    TooManyClusters(u64),
    #[error("{0} clusters is too few for this file system, use a smaller cluster size")]
    TooFewClusters(u64),
    #[error("invalid FAT volume label {0:?}")]
    InvalidLabel(String),
}
```

`crates/rufus-fat/src/lib.rs`:
```rust
//! FAT16 and FAT32 formatters ported from Rufus.

mod error;
mod fat32;
mod label;
mod time;

pub use error::FatError;
pub use fat32::{default_fat32_cluster_size, fat32_geometry, format_fat32};
pub use label::label_bytes;
pub use time::{LocalTime, volume_id};

/// Options shared by the FAT formatters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FatOptions {
    /// Cluster size in bytes; 0 selects the upstream default.
    pub cluster_size: u32,
    /// Already-sanitised label (see `rufus_core::label::to_valid_label`); empty for none.
    pub label: String,
    pub volume_id: u32,
    /// Partition start in sectors (BPB `HiddSec`).
    pub hidden_sectors: u32,
    pub sectors_per_track: u16,
    pub heads: u16,
    /// Timestamp for the volume-label directory entry.
    pub time: LocalTime,
}

impl FatOptions {
    pub fn new(label: &str, time: LocalTime) -> Self {
        Self {
            cluster_size: 0,
            label: label.to_string(),
            volume_id: volume_id(&time),
            hidden_sectors: 0,
            sectors_per_track: 63,
            heads: 255,
            time,
        }
    }
}

/// The on-disk geometry chosen by a formatter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FatSummary {
    pub bytes_per_sector: u32,
    pub sectors_per_cluster: u32,
    pub reserved_sectors: u32,
    pub num_fats: u32,
    pub fat_sectors: u32,
    /// Fixed root directory size (FAT16 only; 0 for FAT32).
    pub root_dir_sectors: u32,
    pub total_sectors: u64,
    pub cluster_count: u64,
}

pub(crate) fn check_sector_size(bytes_per_sector: u32) -> Result<u32, FatError> {
    // upstream: format_fat32.c FormatLargeFAT32 @942ed3a4 — "if (dgDrive.BytesPerSector < 512) BytesPerSector = 512"
    let bps = bytes_per_sector.max(512);
    if bps > 4096 || !bps.is_power_of_two() {
        return Err(FatError::InvalidSectorSize(bps));
    }
    Ok(bps)
}
```

- [ ] **Step 2: Write the failing tests**

`crates/rufus-fat/src/time.rs` (tests):
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn volume_id_matches_upstream_example() {
        // upstream comment: 26 Dec 95, 9:55 PM, 41.94 s -> serial 1D02:3578
        let t = LocalTime { year: 1995, month: 12, day: 26, hour: 21, minute: 55, second: 41, millisecond: 940 };
        assert_eq!(volume_id(&t), 0x1D02_3578);
    }

    #[test]
    fn unix_epoch_and_leap_day() {
        assert_eq!(
            LocalTime::from_unix(0, 0),
            LocalTime { year: 1970, month: 1, day: 1, hour: 0, minute: 0, second: 0, millisecond: 0 }
        );
        assert_eq!(
            LocalTime::from_unix(951_782_400 + 3_723, 5),
            LocalTime { year: 2000, month: 2, day: 29, hour: 1, minute: 2, second: 3, millisecond: 5 }
        );
    }

    #[test]
    fn dos_time_and_date() {
        let t = LocalTime { year: 2024, month: 5, day: 17, hour: 13, minute: 45, second: 31, millisecond: 0 };
        let (time, date) = t.dos_time_date();
        assert_eq!(time, (13 << 11) | (45 << 5) | 15);
        assert_eq!(date, ((2024 - 1980) << 9) | (5 << 5) | 17);
    }
}
```

`crates/rufus-fat/src/label.rs` (tests):
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pads_and_defaults() {
        assert_eq!(&label_bytes("").unwrap(), b"NO NAME    ");
        assert_eq!(&label_bytes("RUFUS").unwrap(), b"RUFUS      ");
        assert_eq!(&label_bytes("ABCDEFGHIJK").unwrap(), b"ABCDEFGHIJK");
    }

    #[test]
    fn rejects_unsanitised_labels() {
        for bad in ["lower", "TWELVE_CHARS", "A*B", "A.B", "ÜBER"] {
            assert!(label_bytes(bad).is_err(), "{bad}");
        }
    }
}
```

`crates/rufus-fat/src/fat32.rs` (tests):
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FatOptions, LocalTime};
    use rufus_blockdev::MemDevice;

    const MIB: u64 = 1 << 20;
    const GIB: u64 = 1 << 30;

    fn summary(len: u64, bps: u32) -> FatSummary {
        fat32_geometry(len, bps, 0).unwrap()
    }

    #[test]
    fn default_cluster_sizes() {
        assert_eq!(default_fat32_cluster_size(63 * MIB), 512);
        assert_eq!(default_fat32_cluster_size(100 * MIB), 1024);
        assert_eq!(default_fat32_cluster_size(200 * MIB), 2048);
        assert_eq!(default_fat32_cluster_size(4 * GIB), 4096);
        assert_eq!(default_fat32_cluster_size(8 * GIB), 8192);
        assert_eq!(default_fat32_cluster_size(20 * GIB), 16384);
        assert_eq!(default_fat32_cluster_size(64 * GIB), 32768);
        assert_eq!(default_fat32_cluster_size(3 << 40), 65536);
    }

    #[test]
    fn geometry_matches_upstream_arithmetic() {
        let s = summary(8 * GIB, 512);
        assert_eq!(
            (s.sectors_per_cluster, s.fat_sectors, s.reserved_sectors, s.cluster_count),
            (16, 8185, 2062, 1_047_424)
        );
        let s = summary(64 * GIB, 512);
        assert_eq!(
            (s.sectors_per_cluster, s.fat_sectors, s.reserved_sectors, s.cluster_count),
            (64, 16381, 2054, 2_096_608)
        );
        let s = summary(GIB, 4096);
        assert_eq!(
            (s.sectors_per_cluster, s.fat_sectors, s.reserved_sectors, s.cluster_count),
            (1, 256, 256, 261_376)
        );
        let s = summary(100 * MIB, 512);
        assert_eq!(
            (s.sectors_per_cluster, s.fat_sectors, s.reserved_sectors, s.cluster_count),
            (2, 794, 460, 101_376)
        );
    }

    #[test]
    fn fat32_256mib_default_is_too_few_clusters() {
        assert!(matches!(fat32_geometry(256 * MIB, 512, 0), Err(FatError::TooFewClusters(65_280))));
    }

    #[test]
    fn size_and_cluster_limits() {
        assert!(matches!(fat32_geometry(16 * MIB, 512, 0), Err(FatError::TooSmall)));
        assert!(matches!(fat32_geometry(8 * GIB, 512, 3000), Err(FatError::InvalidClusterSize(3000))));
        assert!(matches!(fat32_geometry(8 * GIB, 4096, 2048), Err(FatError::InvalidClusterSize(2048))));
        assert!(matches!(fat32_geometry(8 * GIB, 8192, 0), Err(FatError::InvalidSectorSize(8192))));
    }

    #[test]
    fn writes_boot_sector_fsinfo_backup_and_fat() {
        let mut dev = MemDevice::new((100 * MIB) as usize, 512);
        let t = LocalTime { year: 2026, month: 9, day: 25, hour: 12, minute: 0, second: 0, millisecond: 0 };
        let mut opts = FatOptions::new("RUFUSTEST", t);
        opts.hidden_sectors = 2048;
        let s = format_fat32(&mut dev, &opts).unwrap();
        let b = dev.as_bytes();
        assert_eq!(&b[0..3], &[0xEB, 0x58, 0x90]);
        assert_eq!(&b[3..11], b"MSWIN4.1");
        assert_eq!(u16::from_le_bytes([b[11], b[12]]), 512);
        assert_eq!(b[13], 2);
        assert_eq!(u16::from_le_bytes([b[14], b[15]]), 460);
        assert_eq!(b[21], 0xF8);
        assert_eq!(u32::from_le_bytes(b[28..32].try_into().unwrap()), 2048);
        assert_eq!(u32::from_le_bytes(b[36..40].try_into().unwrap()), 794);
        assert_eq!(u32::from_le_bytes(b[67..71].try_into().unwrap()), opts.volume_id);
        assert_eq!(&b[71..82], b"RUFUSTEST  ");
        assert_eq!(&b[82..90], b"FAT32   ");
        assert_eq!(&b[510..512], &[0x55, 0xAA]);
        // FSInfo, and the backup boot sector + FSInfo at sectors 6 and 7
        assert_eq!(&b[512..516], &0x4161_5252u32.to_le_bytes());
        assert_eq!(u32::from_le_bytes(b[512 + 488..512 + 492].try_into().unwrap()), 101_375);
        assert_eq!(&b[6 * 512..7 * 512], &b[0..512]);
        assert_eq!(&b[7 * 512..8 * 512], &b[512..1024]);
        // both FATs start with the media/EOC entries
        for fat in 0..2u64 {
            let off = ((460 + fat * 794) * 512) as usize;
            assert_eq!(&b[off..off + 12], &[0xF8, 0xFF, 0xFF, 0x0F, 0xFF, 0xFF, 0xFF, 0x0F, 0xFF, 0xFF, 0xFF, 0x0F]);
        }
        // the volume label entry is the first root directory entry
        let root = ((460 + 2 * 794) * 512) as usize;
        assert_eq!(&b[root..root + 11], b"RUFUSTEST  ");
        assert_eq!(b[root + 11], 0x08);
        assert_eq!(s.cluster_count, 101_376);
    }
}
```

`crates/rufus-fat/tests/fat32_tools.rs`:
```rust
#![cfg(target_os = "linux")]

use rufus_blockdev::FileDevice;
use rufus_fat::{FatOptions, LocalTime, format_fat32};
use std::path::Path;
use std::process::Command;

fn format(path: &Path, len: u64, sector_size: u32, label: &str) {
    let mut dev = FileDevice::create(path, len, sector_size).unwrap();
    format_fat32(&mut dev, &FatOptions::new(label, LocalTime::from_unix(1_790_000_000, 0))).unwrap();
}

fn fsck_clean(path: &Path) {
    let out = Command::new("fsck.fat").args(["-n", "-v"]).arg(path).output().expect("fsck.fat is installed");
    assert!(
        out.status.success(),
        "fsck.fat failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn fat32_passes_fsck_and_mtools_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let img = dir.path().join("fat32.img");
    format(&img, 100 << 20, 512, "RUFUSTEST");
    fsck_clean(&img);

    let label = Command::new("fatlabel").arg(&img).output().unwrap();
    assert_eq!(String::from_utf8_lossy(&label.stdout).trim(), "RUFUSTEST");

    let src = dir.path().join("hello.txt");
    std::fs::write(&src, b"hello from rufus-rs\n").unwrap();
    let mcopy = Command::new("mcopy")
        .env("MTOOLS_SKIP_CHECK", "1")
        .arg("-i")
        .arg(&img)
        .arg(&src)
        .arg("::/HELLO.TXT")
        .status()
        .expect("mtools is installed");
    assert!(mcopy.success());
    let mtype = Command::new("mtype")
        .env("MTOOLS_SKIP_CHECK", "1")
        .arg("-i")
        .arg(&img)
        .arg("::/HELLO.TXT")
        .output()
        .unwrap();
    assert_eq!(mtype.stdout, b"hello from rufus-rs\n");
    fsck_clean(&img);
}

#[test]
fn fat32_4k_sector_fsck() {
    let dir = tempfile::tempdir().unwrap();
    let img = dir.path().join("fat32-4k.img");
    format(&img, 1 << 30, 4096, "");
    fsck_clean(&img);
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test -p rufus-fat`
Expected: compile errors (modules `time`, `label`, `fat32` are empty).

- [ ] **Step 4: Implement `time.rs`**

```rust
/// A broken-down wall-clock time, as used for volume IDs and DOS timestamps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub millisecond: u16,
}

impl LocalTime {
    /// Calendar time for `secs` since the Unix epoch, taken as UTC.
    /// (Front ends pass local time from the platform layer; the CLI uses UTC.)
    pub fn from_unix(secs: i64, millisecond: u16) -> LocalTime {
        let days = secs.div_euclid(86_400);
        let rem = secs.rem_euclid(86_400);
        // Howard Hinnant's civil_from_days
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = doy - (153 * mp + 2) / 5 + 1;
        let month = if mp < 10 { mp + 3 } else { mp - 9 };
        let year = yoe + era * 400 + i64::from(month <= 2);
        LocalTime {
            year: year as u16,
            month: month as u8,
            day: day as u8,
            hour: (rem / 3600) as u8,
            minute: (rem % 3600 / 60) as u8,
            second: (rem % 60) as u8,
            millisecond,
        }
    }

    /// Packed DOS `(time, date)`; years before 1980 clamp to 1980.
    pub fn dos_time_date(&self) -> (u16, u16) {
        let time = (u16::from(self.hour) << 11) | (u16::from(self.minute) << 5) | u16::from(self.second / 2);
        let year = self.year.max(1980) - 1980;
        let date = (year << 9) | (u16::from(self.month) << 5) | u16::from(self.day);
        (time, date)
    }
}

/// Volume serial number derived from the format time, as DOS does it.
/// upstream: format_fat32.c GetVolumeID @942ed3a4
pub fn volume_id(t: &LocalTime) -> u32 {
    let lo = u16::from(t.day)
        .wrapping_add(u16::from(t.month) << 8)
        .wrapping_add((t.millisecond / 10).wrapping_add(u16::from(t.second) << 8));
    let hi = u16::from(t.minute)
        .wrapping_add(u16::from(t.hour) << 8)
        .wrapping_add(t.year);
    u32::from(lo) | (u32::from(hi) << 16)
}
```

- [ ] **Step 5: Implement `label.rs`**

```rust
use crate::{FatError, LocalTime};

const INVALID: &[u8] = b"*?,;:/\\|+=<>[]\".";

/// Pads an already-sanitised label to the 11-byte on-disk form. An empty
/// label becomes `NO NAME    `, the value upstream writes before setting one.
pub fn label_bytes(label: &str) -> Result<[u8; 11], FatError> {
    if label.is_empty() {
        return Ok(*b"NO NAME    ");
    }
    let valid = label.len() <= 11
        && label
            .bytes()
            .all(|b| (0x20..0x7F).contains(&b) && !b.is_ascii_lowercase() && !INVALID.contains(&b));
    if !valid {
        return Err(FatError::InvalidLabel(label.to_string()));
    }
    let mut out = [b' '; 11];
    out[..label.len()].copy_from_slice(label.as_bytes());
    Ok(out)
}

/// A root-directory volume-label entry (attribute 0x08).
pub(crate) fn label_dir_entry(label: &[u8; 11], t: &LocalTime) -> [u8; 32] {
    let mut e = [0u8; 32];
    e[0..11].copy_from_slice(label);
    e[11] = 0x08;
    let (time, date) = t.dos_time_date();
    e[22..24].copy_from_slice(&time.to_le_bytes());
    e[24..26].copy_from_slice(&date.to_le_bytes());
    e
}
```

- [ ] **Step 6: Implement `fat32.rs`**

```rust
use crate::label::{label_bytes, label_dir_entry};
use crate::{FatError, FatOptions, FatSummary, check_sector_size};
use rufus_blockdev::BlockDevice;

const KB: u64 = 1 << 10;
const MB: u64 = 1 << 20;
const GB: u64 = 1 << 30;
const TB: u64 = 1 << 40;
const NUM_FATS: u32 = 2;
const RECOMMENDED_RESERVED: u32 = 32;
const BACKUP_BOOT_SECTOR: u64 = 6;

/// Microsoft's default FAT32 cluster size for a partition length.
/// upstream: format_fat32.c FormatLargeFAT32 @942ed3a4
pub fn default_fat32_cluster_size(partition_len: u64) -> u32 {
    let size = if partition_len < 64 * MB {
        512
    } else if partition_len < 128 * MB {
        KB
    } else if partition_len < 256 * MB {
        2 * KB
    } else if partition_len < 8 * GB {
        4 * KB
    } else if partition_len < 16 * GB {
        8 * KB
    } else if partition_len < 32 * GB {
        16 * KB
    } else if partition_len < 2 * TB {
        32 * KB
    } else {
        64 * KB
    };
    size as u32
}

/// upstream: format_fat32.c GetFATSizeSectors @942ed3a4
fn fat_size_sectors(total: u32, reserved: u32, sectors_per_cluster: u32, num_fats: u32, bps: u32) -> u32 {
    let numerator = u64::from(total) - u64::from(reserved) + 2 * u64::from(sectors_per_cluster);
    let denominator = u64::from(sectors_per_cluster) * u64::from(bps) / 4 + u64::from(num_fats);
    (numerator / denominator + 1) as u32
}

/// Computes the large-FAT32 geometry without writing anything.
/// upstream: format_fat32.c FormatLargeFAT32 @942ed3a4
pub fn fat32_geometry(partition_len: u64, bytes_per_sector: u32, cluster_size: u32) -> Result<FatSummary, FatError> {
    let bps = check_sector_size(bytes_per_sector)?;
    let total = partition_len / u64::from(bps);
    if total < 65_536 {
        return Err(FatError::TooSmall);
    }
    if total >= 0xFFFF_FFFF {
        return Err(FatError::TooLarge);
    }
    let cluster = if cluster_size == 0 { default_fat32_cluster_size(partition_len) } else { cluster_size };
    if !cluster.is_power_of_two() || cluster < bps || cluster / bps > 128 {
        return Err(FatError::InvalidClusterSize(cluster));
    }
    let spc = cluster / bps;
    let total32 = total as u32;
    // Upstream computes the FAT size before it assigns wRsvdSecCnt, so the
    // reserved sector count it passes here is still 0. Kept for parity.
    let fat = fat_size_sectors(total32, 0, spc, NUM_FATS, bps);
    // Grow the reserved area so the data region starts on a 1 MB boundary.
    let align = (MB / u64::from(bps)) as u32;
    let system = (RECOMMENDED_RESERVED + NUM_FATS * fat).div_ceil(align) * align;
    let reserved = system - NUM_FATS * fat;
    let user = total32.checked_sub(reserved + NUM_FATS * fat).ok_or(FatError::TooSmall)?;
    let clusters = u64::from(user / spc);
    if clusters > 0x0FFF_FFFF {
        return Err(FatError::TooManyClusters(clusters));
    }
    // Fewer than 64K clusters would be misdetected as FAT16.
    if clusters < 65_536 {
        return Err(FatError::TooFewClusters(clusters));
    }
    if (clusters * 4).div_ceil(u64::from(bps)) > u64::from(fat) {
        return Err(FatError::TooLarge);
    }
    Ok(FatSummary {
        bytes_per_sector: bps,
        sectors_per_cluster: spc,
        reserved_sectors: reserved,
        num_fats: NUM_FATS,
        fat_sectors: fat,
        root_dir_sectors: 0,
        total_sectors: total,
        cluster_count: clusters,
    })
}

/// Formats the whole of `dev` as FAT32.
/// upstream: format_fat32.c FormatLargeFAT32 @942ed3a4
pub fn format_fat32(dev: &mut dyn BlockDevice, opts: &FatOptions) -> Result<FatSummary, FatError> {
    let label = label_bytes(&opts.label)?;
    let g = fat32_geometry(dev.len(), dev.sector_size(), opts.cluster_size)?;
    let bps = g.bytes_per_sector as usize;

    let mut boot = vec![0u8; bps];
    boot[0..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
    boot[3..11].copy_from_slice(b"MSWIN4.1");
    boot[11..13].copy_from_slice(&(bps as u16).to_le_bytes());
    boot[13] = g.sectors_per_cluster as u8;
    boot[14..16].copy_from_slice(&(g.reserved_sectors as u16).to_le_bytes());
    boot[16] = NUM_FATS as u8;
    boot[21] = 0xF8;
    boot[24..26].copy_from_slice(&opts.sectors_per_track.to_le_bytes());
    boot[26..28].copy_from_slice(&opts.heads.to_le_bytes());
    boot[28..32].copy_from_slice(&opts.hidden_sectors.to_le_bytes());
    boot[32..36].copy_from_slice(&(g.total_sectors as u32).to_le_bytes());
    boot[36..40].copy_from_slice(&g.fat_sectors.to_le_bytes());
    boot[44..48].copy_from_slice(&2u32.to_le_bytes()); // root directory cluster
    boot[48..50].copy_from_slice(&1u16.to_le_bytes()); // FSInfo sector
    boot[50..52].copy_from_slice(&(BACKUP_BOOT_SECTOR as u16).to_le_bytes());
    boot[64] = 0x80;
    boot[66] = 0x29;
    boot[67..71].copy_from_slice(&opts.volume_id.to_le_bytes());
    boot[71..82].copy_from_slice(&label);
    boot[82..90].copy_from_slice(b"FAT32   ");
    boot[510] = 0x55;
    boot[511] = 0xAA;
    if bps != 512 {
        // Windows only checks offsets 510/511; other OSes may check the end of the sector.
        boot[bps - 2] = 0x55;
        boot[bps - 1] = 0xAA;
    }

    let mut fsinfo = vec![0u8; bps];
    fsinfo[0..4].copy_from_slice(&0x4161_5252u32.to_le_bytes());
    fsinfo[484..488].copy_from_slice(&0x6141_7272u32.to_le_bytes());
    fsinfo[488..492].copy_from_slice(&((g.cluster_count - 1) as u32).to_le_bytes());
    fsinfo[492..496].copy_from_slice(&3u32.to_le_bytes()); // cluster 2 holds the root dir
    fsinfo[508..512].copy_from_slice(&0xAA55_0000u32.to_le_bytes());

    let mut first_fat_sector = vec![0u8; bps];
    first_fat_sector[0..4].copy_from_slice(&0x0FFF_FFF8u32.to_le_bytes());
    first_fat_sector[4..8].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes());
    first_fat_sector[8..12].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes());

    let b = bps as u64;
    let system = u64::from(g.reserved_sectors) + u64::from(NUM_FATS) * u64::from(g.fat_sectors);
    dev.write_zeros(0, (system + u64::from(g.sectors_per_cluster)) * b)?;
    for start in [0, BACKUP_BOOT_SECTOR] {
        dev.write_at(start * b, &boot)?;
        dev.write_at((start + 1) * b, &fsinfo)?;
    }
    for i in 0..u64::from(NUM_FATS) {
        dev.write_at((u64::from(g.reserved_sectors) + i * u64::from(g.fat_sectors)) * b, &first_fat_sector)?;
    }
    if !opts.label.is_empty() {
        dev.write_at(system * b, &label_dir_entry(&label, &opts.time))?;
    }
    dev.flush()?;
    Ok(g)
}
```

- [ ] **Step 7: Run the tests**

Run: `cargo test -p rufus-fat`
Expected: all unit tests pass; `fat32_passes_fsck_and_mtools_roundtrip` and `fat32_4k_sector_fsck` pass.

- [ ] **Step 8: Commit**

```bash
git add Cargo.toml crates/rufus-fat
git commit -m "feat(fat): port upstream large FAT32 formatter"
```

---

### Task 6: `rufus-fat` — FAT16 formatter

**Files:**
- Create: `crates/rufus-fat/src/fat16.rs`
- Modify: `crates/rufus-fat/src/lib.rs`
- Test: unit tests in `fat16.rs`; `crates/rufus-fat/tests/fat16_tools.rs`

**Interfaces:**
- Consumes: `FatOptions`, `FatSummary`, `FatError`, `check_sector_size`, `label_bytes`, `label_dir_entry` (Task 5).
- Produces:
  - `pub fn default_fat16_cluster_size(disk_size: u64) -> Option<u32>` (`None` at 4 GiB and above)
  - `pub fn fat16_geometry(partition_len: u64, bytes_per_sector: u32, cluster_size: u32) -> Result<FatSummary, FatError>`
  - `pub fn format_fat16(&mut dyn BlockDevice, &FatOptions) -> Result<FatSummary, FatError>`

Parity notes for the implementer:
- Upstream's "FAT" option is FAT16, formatted by Windows `FormatEx`. The default cluster size comes from upstream `SetClusterSizes` (ported below). The on-disk layout follows Microsoft's FAT specification (fatgen103): 1 reserved sector, 2 FATs, 512 root entries, media 0xF8. Exact field parity with `FormatEx` is an open row in `docs/parity.md`, to be checked against the golden files from the Windows VM in M1b.
- The cluster count must be in 4085..=65524, the FAT16 range from fatgen103.

- [ ] **Step 1: Write the failing tests**

`crates/rufus-fat/src/fat16.rs` (tests):
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FatOptions, LocalTime};
    use rufus_blockdev::MemDevice;

    const MIB: u64 = 1 << 20;
    const GIB: u64 = 1 << 30;

    #[test]
    fn default_cluster_sizes_follow_upstream() {
        assert_eq!(default_fat16_cluster_size(16 * MIB), Some(512));
        assert_eq!(default_fat16_cluster_size(100 * MIB), Some(2048));
        assert_eq!(default_fat16_cluster_size(512 * MIB), Some(16_384));
        assert_eq!(default_fat16_cluster_size(2 * GIB), Some(65_536));
        assert_eq!(default_fat16_cluster_size(4 * GIB), None);
    }

    #[test]
    fn geometry_vectors() {
        let g = |len, cl| {
            let s = fat16_geometry(len, 512, cl).unwrap();
            (s.sectors_per_cluster, s.fat_sectors, s.root_dir_sectors, s.cluster_count)
        };
        assert_eq!(g(16 * MIB, 0), (1, 127, 32, 32_481));
        assert_eq!(g(100 * MIB, 0), (4, 200, 32, 51_091));
        assert_eq!(g(512 * MIB, 0), (32, 128, 32, 32_758));
        assert_eq!(g(2 * GIB, 0), (128, 128, 32, 32_765));
    }

    #[test]
    fn cluster_count_limits() {
        assert!(matches!(fat16_geometry(100 * MIB, 512, 32_768), Err(FatError::TooFewClusters(3199))));
        assert!(matches!(fat16_geometry(4 * GIB - 1, 512, 65_536), Err(FatError::TooManyClusters(65_531))));
        assert!(matches!(fat16_geometry(4 * GIB, 512, 0), Err(FatError::TooLarge)));
    }

    #[test]
    fn writes_fat16_boot_sector() {
        let mut dev = MemDevice::new((100 * MIB) as usize, 512);
        let t = LocalTime { year: 2026, month: 9, day: 25, hour: 12, minute: 0, second: 0, millisecond: 0 };
        let opts = FatOptions::new("SMALL", t);
        format_fat16(&mut dev, &opts).unwrap();
        let b = dev.as_bytes();
        assert_eq!(&b[0..3], &[0xEB, 0x3C, 0x90]);
        assert_eq!(b[13], 4);
        assert_eq!(u16::from_le_bytes([b[14], b[15]]), 1);
        assert_eq!(u16::from_le_bytes([b[17], b[18]]), 512);
        assert_eq!(u16::from_le_bytes([b[19], b[20]]), 0); // > 65535 sectors -> 32-bit field
        assert_eq!(u32::from_le_bytes(b[32..36].try_into().unwrap()), 204_800);
        assert_eq!(u16::from_le_bytes([b[22], b[23]]), 200);
        assert_eq!(&b[43..54], b"SMALL      ");
        assert_eq!(&b[54..62], b"FAT16   ");
        assert_eq!(&b[512..516], &[0xF8, 0xFF, 0xFF, 0xFF]);
        let root = (1 + 2 * 200) * 512;
        assert_eq!(&b[root..root + 11], b"SMALL      ");
    }
}
```

`crates/rufus-fat/tests/fat16_tools.rs`:
```rust
#![cfg(target_os = "linux")]

use rufus_blockdev::FileDevice;
use rufus_fat::{FatOptions, LocalTime, format_fat16};
use std::process::Command;

#[test]
fn fat16_passes_fsck_and_mtools() {
    let dir = tempfile::tempdir().unwrap();
    let img = dir.path().join("fat16.img");
    let mut dev = FileDevice::create(&img, 100 << 20, 512).unwrap();
    format_fat16(&mut dev, &FatOptions::new("SMALL", LocalTime::from_unix(1_790_000_000, 0))).unwrap();
    drop(dev);

    let fsck = Command::new("fsck.fat").args(["-n", "-v"]).arg(&img).output().unwrap();
    assert!(fsck.status.success(), "{}", String::from_utf8_lossy(&fsck.stdout));

    let src = dir.path().join("a.txt");
    std::fs::write(&src, b"fat16").unwrap();
    assert!(Command::new("mcopy")
        .env("MTOOLS_SKIP_CHECK", "1")
        .arg("-i").arg(&img).arg(&src).arg("::/A.TXT")
        .status().unwrap().success());
    let fsck = Command::new("fsck.fat").arg("-n").arg(&img).status().unwrap();
    assert!(fsck.success());
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p rufus-fat`
Expected: compile errors (`fat16_geometry`, `format_fat16` undefined).

- [ ] **Step 3: Implement `fat16.rs`**

```rust
use crate::label::{label_bytes, label_dir_entry};
use crate::{FatError, FatOptions, FatSummary, check_sector_size};
use rufus_blockdev::BlockDevice;

const MB: u64 = 1 << 20;
const GB: u64 = 1 << 30;
const NUM_FATS: u32 = 2;
const RESERVED: u32 = 1;
const ROOT_ENTRIES: u32 = 512;

/// Upstream's default FAT16 cluster size for a disk size.
/// upstream: rufus.c SetClusterSizes @942ed3a4
pub fn default_fat16_cluster_size(disk_size: u64) -> Option<u32> {
    if disk_size >= 4 * GB {
        return None;
    }
    let mut i = 32u64;
    while i <= 4096 {
        if disk_size < i * MB {
            return Some((16 * i) as u32);
        }
        i <<= 1;
    }
    None
}

/// FAT16 geometry per Microsoft's FAT specification (fatgen103).
pub fn fat16_geometry(partition_len: u64, bytes_per_sector: u32, cluster_size: u32) -> Result<FatSummary, FatError> {
    let bps = check_sector_size(bytes_per_sector)?;
    let total = partition_len / u64::from(bps);
    let cluster = if cluster_size == 0 {
        default_fat16_cluster_size(partition_len).ok_or(FatError::TooLarge)?
    } else {
        cluster_size
    };
    if !cluster.is_power_of_two() || cluster < bps || cluster / bps > 128 {
        return Err(FatError::InvalidClusterSize(cluster));
    }
    let spc = u64::from(cluster / bps);
    let root_dir_sectors = (u64::from(ROOT_ENTRIES) * 32).div_ceil(u64::from(bps));
    let tmp1 = total
        .checked_sub(u64::from(RESERVED) + root_dir_sectors)
        .ok_or(FatError::TooSmall)?;
    // fatgen103: TmpVal2 = (256 * SecPerClus) + NumFATs, where 256 = FAT16 entries per 512-byte sector
    let tmp2 = u64::from(bps) / 2 * spc + u64::from(NUM_FATS);
    let fat = tmp1.div_ceil(tmp2);
    let data = total
        .checked_sub(u64::from(RESERVED) + u64::from(NUM_FATS) * fat + root_dir_sectors)
        .ok_or(FatError::TooSmall)?;
    let clusters = data / spc;
    if clusters < 4085 {
        return Err(FatError::TooFewClusters(clusters));
    }
    if clusters > 65_524 {
        return Err(FatError::TooManyClusters(clusters));
    }
    Ok(FatSummary {
        bytes_per_sector: bps,
        sectors_per_cluster: spc as u32,
        reserved_sectors: RESERVED,
        num_fats: NUM_FATS,
        fat_sectors: fat as u32,
        root_dir_sectors: root_dir_sectors as u32,
        total_sectors: total,
        cluster_count: clusters,
    })
}

/// Formats the whole of `dev` as FAT16.
pub fn format_fat16(dev: &mut dyn BlockDevice, opts: &FatOptions) -> Result<FatSummary, FatError> {
    let label = label_bytes(&opts.label)?;
    let g = fat16_geometry(dev.len(), dev.sector_size(), opts.cluster_size)?;
    let bps = g.bytes_per_sector as usize;

    let mut boot = vec![0u8; bps];
    boot[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
    boot[3..11].copy_from_slice(b"MSWIN4.1");
    boot[11..13].copy_from_slice(&(bps as u16).to_le_bytes());
    boot[13] = g.sectors_per_cluster as u8;
    boot[14..16].copy_from_slice(&(RESERVED as u16).to_le_bytes());
    boot[16] = NUM_FATS as u8;
    boot[17..19].copy_from_slice(&(ROOT_ENTRIES as u16).to_le_bytes());
    if g.total_sectors < 65_536 {
        boot[19..21].copy_from_slice(&(g.total_sectors as u16).to_le_bytes());
    } else {
        boot[32..36].copy_from_slice(&(g.total_sectors as u32).to_le_bytes());
    }
    boot[21] = 0xF8;
    boot[22..24].copy_from_slice(&(g.fat_sectors as u16).to_le_bytes());
    boot[24..26].copy_from_slice(&opts.sectors_per_track.to_le_bytes());
    boot[26..28].copy_from_slice(&opts.heads.to_le_bytes());
    boot[28..32].copy_from_slice(&opts.hidden_sectors.to_le_bytes());
    boot[36] = 0x80;
    boot[38] = 0x29;
    boot[39..43].copy_from_slice(&opts.volume_id.to_le_bytes());
    boot[43..54].copy_from_slice(&label);
    boot[54..62].copy_from_slice(b"FAT16   ");
    boot[510] = 0x55;
    boot[511] = 0xAA;
    if bps != 512 {
        boot[bps - 2] = 0x55;
        boot[bps - 1] = 0xAA;
    }

    let mut first_fat_sector = vec![0u8; bps];
    first_fat_sector[0..4].copy_from_slice(&[0xF8, 0xFF, 0xFF, 0xFF]);

    let b = bps as u64;
    let fats_end = u64::from(RESERVED) + u64::from(NUM_FATS) * u64::from(g.fat_sectors);
    dev.write_zeros(0, (fats_end + u64::from(g.root_dir_sectors)) * b)?;
    dev.write_at(0, &boot)?;
    for i in 0..u64::from(NUM_FATS) {
        dev.write_at((u64::from(RESERVED) + i * u64::from(g.fat_sectors)) * b, &first_fat_sector)?;
    }
    if !opts.label.is_empty() {
        dev.write_at(fats_end * b, &label_dir_entry(&label, &opts.time))?;
    }
    dev.flush()?;
    Ok(g)
}
```

In `crates/rufus-fat/src/lib.rs` add `mod fat16;` and:
```rust
pub use fat16::{default_fat16_cluster_size, fat16_geometry, format_fat16};
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p rufus-fat`
Expected: all FAT16 and FAT32 tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/rufus-fat
git commit -m "feat(fat): FAT16 formatter with upstream default cluster sizes"
```

---

### Task 7: `rufus-iso` — fixtures, volume descriptors, directory records, plain ISO9660

**Files:**
- Create: `crates/rufus-iso/Cargo.toml`, `crates/rufus-iso/src/{lib.rs,error.rs,bytes.rs,volume.rs,record.rs,reader.rs}`
- Create: `crates/rufus-iso/tests/fixtures/make-fixtures.sh` and the generated `plain.iso`, `rrjoliet.iso`, `eltorito.iso`
- Create: `.gitattributes`
- Modify: `Cargo.toml` (members, workspace deps)
- Test: unit tests in `record.rs`; `crates/rufus-iso/tests/common/mod.rs`, `crates/rufus-iso/tests/plain.rs`

**Interfaces:**
- Consumes: nothing from earlier tasks. The ISO input is any `Read + Seek`.
- Produces:
  - `pub enum IsoError { Io(io::Error), NotIso, UnsupportedBlockSize(u16), Corrupt(&'static str), Truncated, NotADirectory, IsADirectory }`
  - `pub struct IsoOptions { pub joliet: bool, pub rock_ridge: bool }` (Default: both `true`)
  - `pub struct Extent { pub lba: u32, pub len: u32 }`, `pub struct IsoTime { pub year: u16, pub month: u8, pub day: u8, pub hour: u8, pub minute: u8, pub second: u8, pub gmt_offset_quarters: i8 }`
  - `pub struct Entry { pub name: String, pub is_dir: bool, pub size: u64, pub extents: Vec<Extent>, pub mtime: IsoTime, pub rock_ridge: bool, pub symlink: Option<String>, pub mode: Option<u32>, pub relocated: bool }`
  - `pub struct IsoReader<R>` with `open(R, IsoOptions) -> Result<Self, IsoError>`, `volume_id(&self) -> &str`, `block_count(&self) -> u32`, `joliet_level(&self) -> u8`, `has_rock_ridge(&self) -> bool`, `root(&self) -> Entry`, `read_dir(&mut self, &Entry) -> Result<Vec<Entry>, IsoError>`, `lookup(&mut self, path: &str) -> Result<Option<Entry>, IsoError>`, `read_file(&mut self, &Entry, &mut dyn Write) -> Result<u64, IsoError>`
  - `pub fn translate_name(name: &str, joliet: bool) -> String`
  - `pub const BLOCK_SIZE: usize = 2048`

Parity notes for the implementer:
- Name translation reproduces libcdio's `iso9660_name_translate_ext`, which upstream uses for non-Rock-Ridge names. Without Joliet, names are lowercased; a trailing `;1` or `.;1` is dropped; any other `;` becomes `.`.
- The *policy* for picking extensions (upstream scans with Joliet disabled, then extracts with Joliet unless Rock Ridge long names or symlinks are present) belongs to the core in M1b. This crate only obeys `IsoOptions`.
- UDF reading is M2. Upstream tries UDF first; in M1a, an ISO9660+UDF bridge image is read through its ISO9660 tree.
- `volume_id()` is always the Primary Volume Descriptor's ID, which is what upstream reports, because it scans with Joliet disabled.

- [ ] **Step 1: Generate the fixtures**

Install xorriso if needed (`sudo pacman -S --needed libisoburn`).

`crates/rufus-iso/tests/fixtures/make-fixtures.sh`:
```sh
#!/bin/sh
# Regenerates the ISO test fixtures. Requires xorriso
# (Arch: libisoburn, Debian/Ubuntu: xorriso).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Tree shared by all fixtures
mkdir -p "$work/base/EFI/BOOT" "$work/base/boot/grub"
printf 'hello from rufus-rs\n' > "$work/base/README.TXT"
printf 'efi-bootloader' > "$work/base/EFI/BOOT/BOOTX64.EFI"
printf 'set timeout=5\n' > "$work/base/boot/grub/grub.cfg"

# Rock Ridge + Joliet tree: a long name, a symlink and 10 levels of directories
cp -R "$work/base" "$work/full"
mkdir -p "$work/full/docs" "$work/full/deep/d1/d2/d3/d4/d5/d6/d7/d8/d9"
head -c 5000 /dev/zero | tr '\0' 'a' \
  > "$work/full/docs/this_is_a_very_long_file_name_used_to_test_rock_ridge_names_longer_than_64.txt"
ln -s ../README.TXT "$work/full/docs/readme-link"
printf 'deep\n' > "$work/full/deep/d1/d2/d3/d4/d5/d6/d7/d8/d9/leaf.txt"

# El Torito tree: BIOS and EFI boot images
cp -R "$work/base" "$work/boot"
head -c 2048 /dev/zero | tr '\0' 'B' > "$work/boot/boot/bios.img"
head -c 4096 /dev/zero | tr '\0' 'E' > "$work/boot/boot/efi.img"

mk() { xorriso -report_about SORRY -as mkisofs -no-pad "$@"; }
mk -iso-level 3 -V PLAIN_VOL -o "$here/plain.iso" "$work/base"
mk -iso-level 3 -R -J -joliet-long -V RRJ_VOL -o "$here/rrjoliet.iso" "$work/full"
mk -iso-level 3 -R -V BOOT_VOL \
   -b boot/bios.img -no-emul-boot -boot-load-size 4 \
   -eltorito-alt-boot -e boot/efi.img -no-emul-boot \
   -o "$here/eltorito.iso" "$work/boot"
ls -l "$here"/*.iso
```

Run: `chmod +x crates/rufus-iso/tests/fixtures/make-fixtures.sh && crates/rufus-iso/tests/fixtures/make-fixtures.sh`
Expected: three `.iso` files, each under 1 MiB.

`.gitattributes`:
```
*.iso binary
```

- [ ] **Step 2: Create the crate skeleton**

Root `Cargo.toml`: add `"crates/rufus-iso"` to `members` and `rufus-iso = { path = "crates/rufus-iso" }` to `[workspace.dependencies]`.

`crates/rufus-iso/Cargo.toml`:
```toml
[package]
name = "rufus-iso"
description = "ISO9660 / Joliet / Rock Ridge / El Torito reader for rufus-rs"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true

[dependencies]
thiserror.workspace = true

[lints]
workspace = true
```

`crates/rufus-iso/src/error.rs`:
```rust
use std::io;

/// Errors from reading an ISO image. Malformed input always yields one of
/// these; the reader never panics on bad data.
#[derive(Debug, thiserror::Error)]
pub enum IsoError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("not an ISO9660 image")]
    NotIso,
    #[error("unsupported logical block size {0}")]
    UnsupportedBlockSize(u16),
    #[error("corrupt image: {0}")]
    Corrupt(&'static str),
    #[error("the image is truncated")]
    Truncated,
    #[error("not a directory")]
    NotADirectory,
    #[error("is a directory")]
    IsADirectory,
}
```

`crates/rufus-iso/src/bytes.rs`:
```rust
pub(crate) fn le16(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}

pub(crate) fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}
```

`crates/rufus-iso/src/lib.rs`:
```rust
//! Read-only ISO9660 reader with Joliet, Rock Ridge and El Torito support.

mod bytes;
mod error;
mod reader;
mod record;
mod volume;

pub use error::IsoError;
pub use reader::{Entry, IsoOptions, IsoReader};
pub use record::{Extent, IsoTime, translate_name};

/// ISO9660 logical block size.
pub const BLOCK_SIZE: usize = 2048;
```

- [ ] **Step 3: Write the failing tests**

`crates/rufus-iso/src/record.rs` (tests):
```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn rec(name: &[u8], lba: u32, len: u32, flags: u8) -> Vec<u8> {
        let mut r = vec![0u8; 33];
        r[2..6].copy_from_slice(&lba.to_le_bytes());
        r[6..10].copy_from_slice(&lba.to_be_bytes());
        r[10..14].copy_from_slice(&len.to_le_bytes());
        r[14..18].copy_from_slice(&len.to_be_bytes());
        r[18..25].copy_from_slice(&[126, 9, 25, 12, 30, 15, 8]);
        r[25] = flags;
        r[32] = name.len() as u8;
        r.extend_from_slice(name);
        if name.len() % 2 == 0 {
            r.push(0);
        }
        r[0] = r.len() as u8;
        r
    }

    #[test]
    fn parses_a_record() {
        let bytes = rec(b"README.TXT;1", 20, 100, 0);
        let (r, used) = parse_record(&bytes).unwrap().unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!((r.lba, r.len, r.flags), (20, 100, 0));
        assert_eq!(r.name, b"README.TXT;1");
        assert_eq!(r.time.year, 2026);
        assert_eq!((r.time.month, r.time.day, r.time.gmt_offset_quarters), (9, 25, 8));
    }

    #[test]
    fn record_length_overflow_is_corrupt() {
        let mut bytes = rec(b"A", 1, 1, 0);
        bytes[0] = 200;
        assert!(matches!(parse_record(&bytes), Err(IsoError::Corrupt(_))));
        let mut bytes = rec(b"A", 1, 1, 0);
        bytes[32] = 60;
        assert!(matches!(parse_record(&bytes), Err(IsoError::Corrupt(_))));
    }

    #[test]
    fn directory_skips_sector_padding() {
        let mut data = vec![0u8; 2 * BLOCK_SIZE];
        let a = rec(b"A;1", 30, 1, 0);
        let b = rec(b"B;1", 31, 1, 0);
        data[..a.len()].copy_from_slice(&a);
        data[BLOCK_SIZE..BLOCK_SIZE + b.len()].copy_from_slice(&b);
        let names: Vec<_> = parse_directory(&data).unwrap().into_iter().map(|r| r.name).collect();
        assert_eq!(names, vec![b"A;1".to_vec(), b"B;1".to_vec()]);
    }

    #[test]
    fn groups_multi_extent_files() {
        let records = vec![
            parse_record(&rec(b"BIG;1", 10, 4096, FLAG_MULTI_EXTENT)).unwrap().unwrap().0,
            parse_record(&rec(b"BIG;1", 20, 100, 0)).unwrap().unwrap().0,
            parse_record(&rec(b"SMALL;1", 30, 5, 0)).unwrap().unwrap().0,
        ];
        let groups = group_extents(records).unwrap();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].extents, vec![Extent { lba: 10, len: 4096 }, Extent { lba: 20, len: 100 }]);
        assert_eq!(groups[0].size, 4196);
        assert_eq!(groups[1].size, 5);
    }

    #[test]
    fn unterminated_multi_extent_is_corrupt() {
        let records = vec![parse_record(&rec(b"BIG;1", 10, 4096, FLAG_MULTI_EXTENT)).unwrap().unwrap().0];
        assert!(matches!(group_extents(records), Err(IsoError::Corrupt(_))));
    }

    #[test]
    fn translates_names_like_libcdio() {
        assert_eq!(translate_name("README.TXT;1", false), "readme.txt");
        assert_eq!(translate_name("FOO.;1", false), "foo");
        assert_eq!(translate_name("FOO;1", false), "foo");
        assert_eq!(translate_name("A;B", false), "a.b");
        assert_eq!(translate_name("Mixed.Txt;1", true), "Mixed.Txt");
        assert_eq!(decode_name(&[0], 0), ".");
        assert_eq!(decode_name(&[1], 0), "..");
        let utf16: Vec<u8> = "Grüße.txt;1".encode_utf16().flat_map(u16::to_be_bytes).collect();
        assert_eq!(decode_name(&utf16, 3), "Grüße.txt");
    }
}
```

`crates/rufus-iso/tests/common/mod.rs`:
```rust
#![allow(dead_code)]

use rufus_iso::{IsoError, IsoReader};
use std::fs::File;
use std::io::{self, Read, Seek};
use std::path::PathBuf;

pub fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
}

pub fn fixture(name: &str) -> File {
    File::open(fixture_path(name)).unwrap()
}

/// Reads a whole file from the image as bytes.
pub fn read<R: Read + Seek>(iso: &mut IsoReader<R>, path: &str) -> Vec<u8> {
    let entry = iso.lookup(path).unwrap().unwrap_or_else(|| panic!("{path} not found"));
    let mut out = Vec::new();
    iso.read_file(&entry, &mut out).unwrap();
    out
}

/// Visits every entry, reading every file; returns the entry count.
pub fn walk<R: Read + Seek>(iso: &mut IsoReader<R>) -> Result<usize, IsoError> {
    let mut stack = vec![iso.root()];
    let mut count = 0;
    while let Some(dir) = stack.pop() {
        for e in iso.read_dir(&dir)? {
            count += 1;
            if e.is_dir {
                stack.push(e);
            } else {
                iso.read_file(&e, &mut io::sink())?;
            }
        }
    }
    Ok(count)
}

pub fn names<R: Read + Seek>(iso: &mut IsoReader<R>, path: &str) -> Vec<String> {
    let dir = iso.lookup(path).unwrap().unwrap();
    let mut n: Vec<String> = iso.read_dir(&dir).unwrap().into_iter().map(|e| e.name).collect();
    n.sort();
    n
}
```

`crates/rufus-iso/tests/plain.rs`:
```rust
mod common;

use common::*;
use rufus_iso::{IsoError, IsoOptions, IsoReader};
use std::io::Cursor;

#[test]
fn opens_plain_iso() {
    let iso = IsoReader::open(fixture("plain.iso"), IsoOptions::default()).unwrap();
    assert_eq!(iso.volume_id(), "PLAIN_VOL");
    assert_eq!(iso.joliet_level(), 0);
    assert!(!iso.has_rock_ridge());
    assert!(iso.block_count() > 16);
}

#[test]
fn plain_names_are_lowercased_without_version() {
    let mut iso = IsoReader::open(fixture("plain.iso"), IsoOptions::default()).unwrap();
    assert_eq!(names(&mut iso, "/"), vec!["boot", "efi", "readme.txt"]);
    assert_eq!(names(&mut iso, "/boot/grub"), vec!["grub.cfg"]);
}

#[test]
fn reads_file_content_and_size() {
    let mut iso = IsoReader::open(fixture("plain.iso"), IsoOptions::default()).unwrap();
    assert_eq!(read(&mut iso, "/efi/boot/bootx64.efi"), b"efi-bootloader");
    let e = iso.lookup("/readme.txt").unwrap().unwrap();
    assert_eq!(e.size, 20);
    assert!(!e.is_dir);
    assert!(iso.lookup("/missing").unwrap().is_none());
    assert!(matches!(iso.read_dir(&e), Err(IsoError::NotADirectory)));
    let dir = iso.lookup("/boot").unwrap().unwrap();
    assert!(matches!(iso.read_file(&dir, &mut Vec::new()), Err(IsoError::IsADirectory)));
}

#[test]
fn not_an_iso() {
    let zeros = Cursor::new(vec![0u8; 64 * 2048]);
    assert!(matches!(IsoReader::open(zeros, IsoOptions::default()), Err(IsoError::NotIso)));
    let empty = Cursor::new(Vec::new());
    assert!(matches!(IsoReader::open(empty, IsoOptions::default()), Err(IsoError::NotIso)));
}

#[test]
fn truncated_image_does_not_panic() {
    let data = std::fs::read(fixture_path("plain.iso")).unwrap();
    for cut in [0, 100, 16 * 2048 + 10, 18 * 2048, data.len() / 2, data.len() - 1] {
        let slice = data[..cut].to_vec();
        if let Ok(mut iso) = IsoReader::open(Cursor::new(slice), IsoOptions::default()) {
            let _ = walk(&mut iso);
        }
    }
    // Cut the image 10 bytes into README.TXT's data: directories (which come
    // before file data) still read, but the file must report truncation.
    let mut full = IsoReader::open(Cursor::new(data.clone()), IsoOptions::default()).unwrap();
    let lba = full.lookup("/readme.txt").unwrap().unwrap().extents[0].lba as usize;
    let short = data[..lba * 2048 + 10].to_vec();
    let mut iso = IsoReader::open(Cursor::new(short), IsoOptions::default()).unwrap();
    let readme = iso.lookup("/readme.txt").unwrap().unwrap();
    assert!(matches!(iso.read_file(&readme, &mut Vec::new()), Err(IsoError::Truncated)));
}
```

- [ ] **Step 4: Run the tests to verify they fail**

Run: `cargo test -p rufus-iso`
Expected: compile errors (`parse_record`, `IsoReader` undefined).

- [ ] **Step 5: Implement `volume.rs`**

```rust
use crate::bytes::{le16, le32};
use crate::{BLOCK_SIZE, IsoError};

pub(crate) struct Pvd {
    pub volume_id: String,
    pub block_count: u32,
    pub root: Vec<u8>,
}

pub(crate) enum Descriptor {
    BootRecord { catalog_lba: Option<u32> },
    Primary(Pvd),
    Terminator,
    Other,
}

fn a_string(b: &[u8]) -> String {
    String::from_utf8_lossy(b).trim_end_matches([' ', '\0']).to_string()
}

/// Parses one 2048-byte volume descriptor.
pub(crate) fn parse_descriptor(b: &[u8]) -> Result<Descriptor, IsoError> {
    if b.len() < BLOCK_SIZE || &b[1..6] != b"CD001" {
        return Err(IsoError::NotIso);
    }
    Ok(match b[0] {
        0 => Descriptor::BootRecord {
            catalog_lba: b[7..].starts_with(b"EL TORITO SPECIFICATION").then(|| le32(&b[71..75])),
        },
        1 => {
            let block_size = le16(&b[128..130]);
            if usize::from(block_size) != BLOCK_SIZE {
                return Err(IsoError::UnsupportedBlockSize(block_size));
            }
            Descriptor::Primary(Pvd {
                volume_id: a_string(&b[40..72]),
                block_count: le32(&b[80..84]),
                root: b[156..190].to_vec(),
            })
        }
        255 => Descriptor::Terminator,
        _ => Descriptor::Other,
    })
}
```

- [ ] **Step 6: Implement `record.rs`**

Put this above the tests:
```rust
use crate::bytes::le32;
use crate::{BLOCK_SIZE, IsoError};

pub(crate) const FLAG_DIR: u8 = 0x02;
pub(crate) const FLAG_MULTI_EXTENT: u8 = 0x80;

/// A contiguous run of blocks holding (part of) a file or directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extent {
    pub lba: u32,
    pub len: u32,
}

/// Directory record timestamp (ECMA-119 9.1.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IsoTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    /// Offset from GMT in 15-minute units.
    pub gmt_offset_quarters: i8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RawRecord {
    pub lba: u32,
    pub len: u32,
    pub flags: u8,
    pub name: Vec<u8>,
    pub time: IsoTime,
    pub system_use: Vec<u8>,
}

/// Parses the record at the start of `b`. Returns `None` at a zero length
/// byte (end of the records in this sector).
pub(crate) fn parse_record(b: &[u8]) -> Result<Option<(RawRecord, usize)>, IsoError> {
    if b.is_empty() || b[0] == 0 {
        return Ok(None);
    }
    let len = usize::from(b[0]);
    if len < 34 || len > b.len() {
        return Err(IsoError::Corrupt("directory record length"));
    }
    let name_len = usize::from(b[32]);
    if 33 + name_len > len {
        return Err(IsoError::Corrupt("directory record name length"));
    }
    let su_start = 33 + name_len + usize::from(name_len % 2 == 0);
    let system_use = if su_start < len { b[su_start..len].to_vec() } else { Vec::new() };
    let t = &b[18..25];
    let record = RawRecord {
        lba: le32(&b[2..6]),
        len: le32(&b[10..14]),
        flags: b[25],
        name: b[33..33 + name_len].to_vec(),
        time: IsoTime {
            year: 1900 + u16::from(t[0]),
            month: t[1],
            day: t[2],
            hour: t[3],
            minute: t[4],
            second: t[5],
            gmt_offset_quarters: t[6] as i8,
        },
        system_use,
    };
    Ok(Some((record, len)))
}

/// Parses all records of a directory. Records never cross a block boundary.
pub(crate) fn parse_directory(data: &[u8]) -> Result<Vec<RawRecord>, IsoError> {
    let mut out = Vec::new();
    for block in data.chunks(BLOCK_SIZE) {
        let mut pos = 0;
        while pos < block.len() {
            match parse_record(&block[pos..])? {
                Some((r, used)) => {
                    out.push(r);
                    pos += used;
                }
                None => break,
            }
        }
    }
    Ok(out)
}

/// One logical directory entry, possibly spread over several extents.
pub(crate) struct Group {
    pub first: RawRecord,
    pub extents: Vec<Extent>,
    pub size: u64,
}

/// Joins multi-extent records (ECMA-119 flag bit 7) into single entries.
pub(crate) fn group_extents(records: Vec<RawRecord>) -> Result<Vec<Group>, IsoError> {
    let mut out = Vec::new();
    let mut current: Option<Group> = None;
    for r in records {
        let extent = Extent { lba: r.lba, len: r.len };
        let more = r.flags & FLAG_MULTI_EXTENT != 0;
        match current.as_mut() {
            Some(g) => {
                g.extents.push(extent);
                g.size += u64::from(r.len);
            }
            None => {
                let size = u64::from(r.len);
                current = Some(Group { first: r, extents: vec![extent], size });
            }
        }
        if !more {
            out.extend(current.take());
        }
    }
    if current.is_some() {
        return Err(IsoError::Corrupt("unterminated multi-extent file"));
    }
    Ok(out)
}

/// libcdio `iso9660_name_translate_ext`: lowercase (unless Joliet), drop a
/// trailing `;1` or `.;1`, and turn any remaining `;` into `.`.
pub fn translate_name(name: &str, joliet: bool) -> String {
    let chars: Vec<char> = name.chars().collect();
    let len = chars.len();
    let mut out = String::with_capacity(name.len());
    for i in 0..len {
        let mut c = chars[i];
        if c == '\0' {
            break;
        }
        if !joliet {
            c = c.to_ascii_lowercase();
        }
        if c == '.' && i + 3 == len && chars[i + 1] == ';' && chars[i + 2] == '1' {
            break;
        }
        if c == ';' && i + 2 == len && chars[i + 1] == '1' {
            break;
        }
        if c == ';' {
            c = '.';
        }
        out.push(c);
    }
    out
}

/// Decodes a raw record name (UCS-2BE when Joliet is active).
pub(crate) fn decode_name(raw: &[u8], joliet_level: u8) -> String {
    match raw {
        [0] => return ".".to_string(),
        [1] => return "..".to_string(),
        _ => {}
    }
    let name = if joliet_level > 0 {
        let units: Vec<u16> = raw.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(raw).into_owned()
    };
    translate_name(&name, joliet_level > 0)
}
```

- [ ] **Step 7: Implement `reader.rs`**

```rust
use crate::record::{FLAG_DIR, Group, decode_name, group_extents, parse_directory, parse_record};
use crate::volume::{Descriptor, parse_descriptor};
use crate::{BLOCK_SIZE, Extent, IsoError, IsoTime};
use std::io::{self, Read, Seek, SeekFrom, Write};

const MAX_DESCRIPTORS: u32 = 64;
const MAX_DIR_SIZE: u64 = 64 << 20;
const MAX_PATH_DEPTH: usize = 256;

/// Which ISO9660 extensions the reader may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IsoOptions {
    pub joliet: bool,
    pub rock_ridge: bool,
}

impl Default for IsoOptions {
    fn default() -> Self {
        Self { joliet: true, rock_ridge: true }
    }
}

/// A file or directory in the image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub extents: Vec<Extent>,
    pub mtime: IsoTime,
    /// The entry carries Rock Ridge information.
    pub rock_ridge: bool,
    /// Rock Ridge symbolic link target.
    pub symlink: Option<String>,
    /// Rock Ridge POSIX mode.
    pub mode: Option<u32>,
    /// A Rock Ridge relocated ("deep") directory reached through a CL link.
    pub relocated: bool,
}

/// Reads an ISO9660 image.
#[derive(Debug)]
pub struct IsoReader<R> {
    src: R,
    volume_id: String,
    block_count: u32,
    joliet_level: u8,
    rock_ridge: bool,
    susp_skip: usize,
    root: Entry,
    boot_catalog_lba: Option<u32>,
}

fn map_eof(e: io::Error) -> IsoError {
    if e.kind() == io::ErrorKind::UnexpectedEof {
        IsoError::Truncated
    } else {
        IsoError::Io(e)
    }
}

fn read_bytes<R: Read + Seek>(src: &mut R, offset: u64, len: usize) -> Result<Vec<u8>, IsoError> {
    src.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; len];
    src.read_exact(&mut buf).map_err(map_eof)?;
    Ok(buf)
}

fn entry_from_record(r: &crate::record::RawRecord, name: String) -> Entry {
    Entry {
        name,
        is_dir: r.flags & FLAG_DIR != 0,
        size: u64::from(r.len),
        extents: vec![Extent { lba: r.lba, len: r.len }],
        mtime: r.time,
        rock_ridge: false,
        symlink: None,
        mode: None,
        relocated: false,
    }
}

impl<R: Read + Seek> IsoReader<R> {
    /// Opens an image and reads its volume descriptors.
    pub fn open(mut src: R, opts: IsoOptions) -> Result<Self, IsoError> {
        let _ = opts; // Joliet and Rock Ridge selection arrive in Tasks 8 and 9.
        let mut pvd = None;
        let mut catalog = None;
        for i in 0..MAX_DESCRIPTORS {
            let parsed = read_bytes(&mut src, u64::from(16 + i) * BLOCK_SIZE as u64, BLOCK_SIZE)
                .and_then(|b| parse_descriptor(&b));
            match parsed {
                Ok(Descriptor::BootRecord { catalog_lba }) => catalog = catalog.or(catalog_lba),
                Ok(Descriptor::Primary(p)) => {
                    if pvd.is_none() {
                        pvd = Some(p);
                    }
                }
                Ok(Descriptor::Terminator) => break,
                Ok(Descriptor::Other) => {}
                Err(IsoError::UnsupportedBlockSize(s)) => return Err(IsoError::UnsupportedBlockSize(s)),
                Err(_) if pvd.is_some() => break,
                Err(_) => return Err(IsoError::NotIso),
            }
        }
        let pvd = pvd.ok_or(IsoError::NotIso)?;
        let (root_record, _) = parse_record(&pvd.root)?.ok_or(IsoError::Corrupt("root directory record"))?;
        let mut root = entry_from_record(&root_record, String::new());
        root.is_dir = true;
        Ok(Self {
            src,
            volume_id: pvd.volume_id,
            block_count: pvd.block_count,
            joliet_level: 0,
            rock_ridge: false,
            susp_skip: 0,
            root,
            boot_catalog_lba: catalog,
        })
    }

    /// The Primary Volume Descriptor's volume identifier.
    pub fn volume_id(&self) -> &str {
        &self.volume_id
    }

    pub fn block_count(&self) -> u32 {
        self.block_count
    }

    /// 0 when the ISO9660 tree is used, otherwise the Joliet level (1-3).
    pub fn joliet_level(&self) -> u8 {
        self.joliet_level
    }

    pub fn has_rock_ridge(&self) -> bool {
        self.rock_ridge
    }

    pub fn root(&self) -> Entry {
        self.root.clone()
    }

    /// Lists a directory, without `.` and `..`.
    pub fn read_dir(&mut self, dir: &Entry) -> Result<Vec<Entry>, IsoError> {
        if !dir.is_dir {
            return Err(IsoError::NotADirectory);
        }
        if dir.size > MAX_DIR_SIZE {
            return Err(IsoError::Corrupt("directory too large"));
        }
        let extent = *dir.extents.first().ok_or(IsoError::Corrupt("directory without extent"))?;
        let data = read_bytes(
            &mut self.src,
            u64::from(extent.lba) * BLOCK_SIZE as u64,
            extent.len as usize,
        )?;
        let mut out = Vec::new();
        for group in group_extents(parse_directory(&data)?)? {
            if matches!(group.first.name.as_slice(), [0] | [1]) {
                continue;
            }
            if let Some(entry) = self.make_entry(group)? {
                out.push(entry);
            }
        }
        Ok(out)
    }

    fn make_entry(&mut self, group: Group) -> Result<Option<Entry>, IsoError> {
        let name = decode_name(&group.first.name, self.joliet_level);
        let mut entry = entry_from_record(&group.first, name);
        entry.size = group.size;
        entry.extents = group.extents;
        Ok(Some(entry))
    }

    /// Finds an entry by `/`-separated path of translated names.
    pub fn lookup(&mut self, path: &str) -> Result<Option<Entry>, IsoError> {
        let mut current = self.root.clone();
        for (depth, component) in path.split('/').filter(|c| !c.is_empty()).enumerate() {
            if depth >= MAX_PATH_DEPTH {
                return Err(IsoError::Corrupt("path too deep"));
            }
            if !current.is_dir {
                return Ok(None);
            }
            match self.read_dir(&current)?.into_iter().find(|e| e.name == component) {
                Some(e) => current = e,
                None => return Ok(None),
            }
        }
        Ok(Some(current))
    }

    /// Copies a file's content to `out`; returns the number of bytes copied.
    pub fn read_file(&mut self, entry: &Entry, out: &mut dyn Write) -> Result<u64, IsoError> {
        if entry.is_dir {
            return Err(IsoError::IsADirectory);
        }
        let mut buf = vec![0u8; 64 * 1024];
        let mut total = 0u64;
        for extent in &entry.extents {
            self.src.seek(SeekFrom::Start(u64::from(extent.lba) * BLOCK_SIZE as u64))?;
            let mut left = u64::from(extent.len);
            while left > 0 {
                let n = left.min(buf.len() as u64) as usize;
                self.src.read_exact(&mut buf[..n]).map_err(map_eof)?;
                out.write_all(&buf[..n])?;
                left -= n as u64;
                total += n as u64;
            }
        }
        Ok(total)
    }
}
```

Note: `susp_skip` and `boot_catalog_lba` are unused until Tasks 9 and 10. If clippy warns about dead fields, add `#[allow(dead_code)]` on those two fields with a comment naming the task that uses them, and remove the attribute in that task.

- [ ] **Step 8: Run the tests**

Run: `cargo test -p rufus-iso`
Expected: all record unit tests and `tests/plain.rs` pass.

- [ ] **Step 9: Commit**

```bash
git add .gitattributes Cargo.toml crates/rufus-iso
git commit -m "feat(iso): ISO9660 reader with libcdio-compatible name translation"
```

---

### Task 8: `rufus-iso` — Joliet

**Files:**
- Modify: `crates/rufus-iso/src/volume.rs`, `crates/rufus-iso/src/reader.rs`
- Test: `crates/rufus-iso/tests/joliet.rs`

**Interfaces:**
- Consumes: `IsoReader`, `IsoOptions`, `decode_name` (Task 7).
- Produces: `IsoReader::open` uses the Joliet tree when `opts.joliet` is set and a Joliet SVD exists; `joliet_level()` then returns 1–3. `volume_id()` stays the PVD identifier.

- [ ] **Step 1: Write the failing test**

`crates/rufus-iso/tests/joliet.rs`:
```rust
mod common;

use common::*;
use rufus_iso::{IsoOptions, IsoReader};

const LONG: &str = "this_is_a_very_long_file_name_used_to_test_rock_ridge_names_longer_than_64.txt";

#[test]
fn joliet_tree_is_used_by_default() {
    let mut iso = IsoReader::open(fixture("rrjoliet.iso"), IsoOptions::default()).unwrap();
    assert!(iso.joliet_level() >= 1);
    assert!(!iso.has_rock_ridge());
    assert_eq!(iso.volume_id(), "RRJ_VOL");
    let root = names(&mut iso, "/");
    for expected in ["EFI", "README.TXT", "boot", "deep", "docs"] {
        assert!(root.iter().any(|n| n == expected), "{expected} missing from {root:?}");
    }
    assert_eq!(read(&mut iso, "/boot/grub/grub.cfg"), b"set timeout=5\n");
    let long = iso.lookup(&format!("/docs/{LONG}")).unwrap().unwrap();
    assert_eq!(long.size, 5000);
}

#[test]
fn joliet_can_be_disabled() {
    let opts = IsoOptions { joliet: false, rock_ridge: false };
    let mut iso = IsoReader::open(fixture("rrjoliet.iso"), opts).unwrap();
    assert_eq!(iso.joliet_level(), 0);
    let root = names(&mut iso, "/");
    assert!(root.iter().any(|n| n == "readme.txt"), "{root:?}");
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p rufus-iso --test joliet`
Expected: FAIL. `joliet_level()` is 0 and the names are lowercased.

- [ ] **Step 3: Parse the Joliet SVD**

In `volume.rs`, add the SVD type and variant and handle descriptor type 2:
```rust
pub(crate) struct Svd {
    pub joliet_level: u8,
    pub root: Vec<u8>,
}
```
Add `Supplementary(Option<Svd>),` to `enum Descriptor`, and add this arm before `255 =>` in `parse_descriptor`:
```rust
        2 => {
            // Joliet escape sequences (UCS-2 level 1/2/3): %/@, %/C, %/E
            let level = match &b[88..91] {
                [0x25, 0x2F, 0x40] => 1,
                [0x25, 0x2F, 0x43] => 2,
                [0x25, 0x2F, 0x45] => 3,
                _ => 0,
            };
            Descriptor::Supplementary((level > 0).then(|| Svd { joliet_level: level, root: b[156..190].to_vec() }))
        }
```

- [ ] **Step 4: Select the tree in `open`**

In `reader.rs` `open`, replace `let _ = opts;` with `let mut joliet = None;`. Add a match arm after the `Primary` one:
```rust
                Ok(Descriptor::Supplementary(Some(svd))) => {
                    if opts.joliet && joliet.is_none() {
                        joliet = Some(svd);
                    }
                }
                Ok(Descriptor::Supplementary(None)) => {}
```
Replace the root computation:
```rust
        let pvd = pvd.ok_or(IsoError::NotIso)?;
        let (root_bytes, joliet_level) = match &joliet {
            Some(svd) => (svd.root.as_slice(), svd.joliet_level),
            None => (pvd.root.as_slice(), 0),
        };
        let (root_record, _) = parse_record(root_bytes)?.ok_or(IsoError::Corrupt("root directory record"))?;
        let mut root = entry_from_record(&root_record, String::new());
        root.is_dir = true;
```
and set `joliet_level,` in the returned struct instead of `joliet_level: 0,`.

- [ ] **Step 5: Run the tests**

Run: `cargo test -p rufus-iso`
Expected: all tests pass, including `tests/joliet.rs`.

- [ ] **Step 6: Commit**

```bash
git add crates/rufus-iso
git commit -m "feat(iso): Joliet support"
```

---

### Task 9: `rufus-iso` — SUSP and Rock Ridge

**Files:**
- Create: `crates/rufus-iso/src/susp.rs`
- Modify: `crates/rufus-iso/src/lib.rs`, `crates/rufus-iso/src/reader.rs`
- Test: unit tests in `susp.rs`; `crates/rufus-iso/tests/rockridge.rs`

**Interfaces:**
- Consumes: `IsoReader`, `Entry`, `Group`, `parse_record`, `read_bytes` (Tasks 7–8).
- Produces:
  - `pub(crate) struct Ce { pub lba: u32, pub offset: u32, pub len: u32 }`
  - `pub(crate) struct RockRidge` with fields `present`, `name: Option<Vec<u8>>`, `symlink: Option<String>`, `mode: Option<u32>`, `child_link: Option<u32>`, `parent_link`, `relocated`, `sp_skip: Option<u8>`
  - `pub(crate) fn parse_with_continuations(area: &[u8], read: impl FnMut(Ce) -> Result<Vec<u8>, IsoError>) -> Result<RockRidge, IsoError>`
  - Behaviour: when Joliet is not in use and `opts.rock_ridge` is set, `open` detects the SUSP `SP` entry in the root `.` record. Entries then use Rock Ridge names (`NM`), symlinks (`SL`) and modes (`PX`). `CL` entries become directories at the relocated location (`Entry::relocated = true`); `RE` entries are hidden.

- [ ] **Step 1: Write the failing tests**

`crates/rufus-iso/src/susp.rs` (tests):
```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn entry(sig: &[u8; 2], data: &[u8]) -> Vec<u8> {
        let mut e = vec![sig[0], sig[1], (4 + data.len()) as u8, 1];
        e.extend_from_slice(data);
        e
    }

    fn no_ce(_: Ce) -> Result<Vec<u8>, IsoError> {
        panic!("unexpected continuation")
    }

    #[test]
    fn sp_entry() {
        let rr = parse_with_continuations(&entry(b"SP", &[0xBE, 0xEF, 0]), no_ce).unwrap();
        assert_eq!(rr.sp_skip, Some(0));
        assert!(!rr.present);
    }

    #[test]
    fn nm_entries_concatenate_and_px_gives_mode() {
        let mut area = entry(b"PX", &[0o100644u32.to_le_bytes(), [0; 4]].concat());
        area.extend(entry(b"NM", &[0x01, b'l', b'o', b'n', b'g']));
        area.extend(entry(b"NM", &[0x00, b'-', b'n', b'a', b'm', b'e']));
        let rr = parse_with_continuations(&area, no_ce).unwrap();
        assert!(rr.present);
        assert_eq!(rr.name.as_deref(), Some(&b"long-name"[..]));
        assert_eq!(rr.mode, Some(0o100644));
    }

    #[test]
    fn symlinks() {
        // ../README.TXT
        let mut data = vec![0u8, 0x04, 0];
        data.extend_from_slice(&[0x00, 10]);
        data.extend_from_slice(b"README.TXT");
        let rr = parse_with_continuations(&entry(b"SL", &data), no_ce).unwrap();
        assert_eq!(rr.symlink.as_deref(), Some("../README.TXT"));

        // /usr/lib, with "li" + "b" continued across two components
        let mut data = vec![0u8, 0x08, 0];
        data.extend_from_slice(&[0x00, 3]);
        data.extend_from_slice(b"usr");
        data.extend_from_slice(&[0x01, 2]);
        data.extend_from_slice(b"li");
        data.extend_from_slice(&[0x00, 1]);
        data.extend_from_slice(b"b");
        let rr = parse_with_continuations(&entry(b"SL", &data), no_ce).unwrap();
        assert_eq!(rr.symlink.as_deref(), Some("/usr/lib"));
    }

    #[test]
    fn relocation_entries() {
        let mut area = entry(b"CL", &[77u32.to_le_bytes(), 77u32.to_be_bytes()].concat());
        area.extend(entry(b"RE", &[]));
        let rr = parse_with_continuations(&area, no_ce).unwrap();
        assert_eq!(rr.child_link, Some(77));
        assert!(rr.relocated);
    }

    #[test]
    fn follows_continuation_area() {
        let ce_data = [
            40u32.to_le_bytes(), 40u32.to_be_bytes(),
            8u32.to_le_bytes(), 8u32.to_be_bytes(),
            9u32.to_le_bytes(), 9u32.to_be_bytes(),
        ]
        .concat();
        let area = entry(b"CE", &ce_data);
        let rr = parse_with_continuations(&area, |ce| {
            assert_eq!((ce.lba, ce.offset, ce.len), (40, 8, 9));
            Ok(entry(b"NM", &[0, b'x', b'y', b'z', b'!']))
        })
        .unwrap();
        assert_eq!(rr.name.as_deref(), Some(&b"xyz!"[..]));
    }

    #[test]
    fn ce_loop_is_bounded() {
        let ce_data = [
            40u32.to_le_bytes(), 40u32.to_be_bytes(),
            0u32.to_le_bytes(), 0u32.to_be_bytes(),
            28u32.to_le_bytes(), 28u32.to_be_bytes(),
        ]
        .concat();
        let area = entry(b"CE", &ce_data);
        let looping = area.clone();
        let r = parse_with_continuations(&area, |_| Ok(looping.clone()));
        assert!(matches!(r, Err(IsoError::Corrupt(_))));
    }

    #[test]
    fn garbage_lengths_stop_parsing() {
        let rr = parse_with_continuations(&[b'N', b'M', 200, 1, 0, b'x'], no_ce).unwrap();
        assert!(rr.name.is_none());
        let rr = parse_with_continuations(&[b'N', b'M', 2, 1], no_ce).unwrap();
        assert!(rr.name.is_none());
    }
}
```

`crates/rufus-iso/tests/rockridge.rs`:
```rust
mod common;

use common::*;
use rufus_iso::{IsoOptions, IsoReader};

const LONG: &str = "this_is_a_very_long_file_name_used_to_test_rock_ridge_names_longer_than_64.txt";
const RR_ONLY: IsoOptions = IsoOptions { joliet: false, rock_ridge: true };

#[test]
fn rock_ridge_names_and_modes() {
    let mut iso = IsoReader::open(fixture("rrjoliet.iso"), RR_ONLY).unwrap();
    assert!(iso.has_rock_ridge());
    assert_eq!(iso.joliet_level(), 0);
    let root = names(&mut iso, "/");
    for expected in ["EFI", "README.TXT", "boot", "deep", "docs"] {
        assert!(root.iter().any(|n| n == expected), "{expected} missing from {root:?}");
    }
    assert_eq!(names(&mut iso, "/boot/grub"), vec!["grub.cfg"]);
    let readme = iso.lookup("/README.TXT").unwrap().unwrap();
    assert!(readme.rock_ridge);
    assert_eq!(readme.mode.unwrap() & 0o170000, 0o100000);
}

#[test]
fn long_names_and_symlinks() {
    let mut iso = IsoReader::open(fixture("rrjoliet.iso"), RR_ONLY).unwrap();
    let long = iso.lookup(&format!("/docs/{LONG}")).unwrap().unwrap();
    assert!(long.name.len() > 64);
    assert_eq!(long.size, 5000);
    let link = iso.lookup("/docs/readme-link").unwrap().unwrap();
    assert_eq!(link.symlink.as_deref(), Some("../README.TXT"));
    assert_eq!(link.size, 0);
}

#[test]
fn deep_directories_are_reachable() {
    let mut iso = IsoReader::open(fixture("rrjoliet.iso"), RR_ONLY).unwrap();
    assert_eq!(read(&mut iso, "/deep/d1/d2/d3/d4/d5/d6/d7/d8/d9/leaf.txt"), b"deep\n");
    walk(&mut iso).unwrap();
}

#[test]
fn rock_ridge_disabled_falls_back_to_iso_names() {
    let mut iso = IsoReader::open(fixture("rrjoliet.iso"), IsoOptions { joliet: false, rock_ridge: false }).unwrap();
    assert!(!iso.has_rock_ridge());
    assert!(names(&mut iso, "/").iter().any(|n| n == "readme.txt"));
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p rufus-iso`
Expected: compile errors in `susp.rs` (`parse_with_continuations` undefined).

- [ ] **Step 3: Implement `susp.rs`**

Above the tests:
```rust
use crate::IsoError;
use crate::bytes::le32;

const MAX_CONTINUATIONS: usize = 32;
const MAX_CONTINUATION_LEN: u32 = 64 * 1024;

/// A SUSP continuation area (CE entry).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Ce {
    pub lba: u32,
    pub offset: u32,
    pub len: u32,
}

/// Rock Ridge data collected from one directory record.
#[derive(Debug, Default)]
pub(crate) struct RockRidge {
    /// Any Rock Ridge entry was present.
    pub present: bool,
    pub name: Option<Vec<u8>>,
    pub symlink: Option<String>,
    pub mode: Option<u32>,
    pub child_link: Option<u32>,
    pub parent_link: bool,
    pub relocated: bool,
    /// From an SP entry: the number of bytes to skip in every system use area.
    pub sp_skip: Option<u8>,
    symlink_parts: Vec<String>,
    symlink_absolute: bool,
    symlink_continues: bool,
}

impl RockRidge {
    fn push_symlink_part(&mut self, part: String) {
        if self.symlink_continues {
            if let Some(last) = self.symlink_parts.last_mut() {
                last.push_str(&part);
                return;
            }
        }
        self.symlink_parts.push(part);
    }

    fn parse_sl(&mut self, mut d: &[u8]) {
        while d.len() >= 2 {
            let flags = d[0];
            let len = usize::from(d[1]);
            if 2 + len > d.len() {
                break;
            }
            let content = &d[2..2 + len];
            if flags & 0x08 != 0 {
                if self.symlink_parts.is_empty() {
                    self.symlink_absolute = true;
                }
            } else if flags & 0x02 != 0 {
                self.push_symlink_part(".".into());
            } else if flags & 0x04 != 0 {
                self.push_symlink_part("..".into());
            } else {
                self.push_symlink_part(String::from_utf8_lossy(content).into_owned());
            }
            self.symlink_continues = flags & 0x01 != 0;
            d = &d[2 + len..];
        }
        let prefix = if self.symlink_absolute { "/" } else { "" };
        self.symlink = Some(format!("{prefix}{}", self.symlink_parts.join("/")));
    }

    /// Parses one system use area. Returns the continuation, if any.
    fn parse_area(&mut self, area: &[u8]) -> Option<Ce> {
        let mut ce = None;
        let mut pos = 0;
        while pos + 4 <= area.len() {
            let sig = [area[pos], area[pos + 1]];
            let len = usize::from(area[pos + 2]);
            if len < 4 || pos + len > area.len() {
                break;
            }
            let data = &area[pos + 4..pos + len];
            match &sig {
                b"SP" if data.len() >= 3 && data[0] == 0xBE && data[1] == 0xEF => self.sp_skip = Some(data[2]),
                b"CE" if data.len() >= 20 => {
                    ce = Some(Ce { lba: le32(&data[0..4]), offset: le32(&data[8..12]), len: le32(&data[16..20]) });
                }
                b"ST" => break,
                b"PX" => {
                    self.present = true;
                    if data.len() >= 4 {
                        self.mode = Some(le32(&data[0..4]));
                    }
                }
                b"NM" => {
                    self.present = true;
                    // bits 1-2 flag "." and ".." names, which we never need
                    if !data.is_empty() && data[0] & 0x06 == 0 {
                        self.name.get_or_insert_with(Vec::new).extend_from_slice(&data[1..]);
                    }
                }
                b"SL" => {
                    self.present = true;
                    if !data.is_empty() {
                        self.parse_sl(&data[1..]);
                    }
                }
                b"CL" => {
                    self.present = true;
                    if data.len() >= 4 {
                        self.child_link = Some(le32(&data[0..4]));
                    }
                }
                b"PL" => {
                    self.present = true;
                    self.parent_link = true;
                }
                b"RE" => {
                    self.present = true;
                    self.relocated = true;
                }
                b"TF" | b"RR" | b"SF" | b"PN" => self.present = true,
                _ => {}
            }
            pos += len;
        }
        ce
    }
}

/// Parses a system use area and follows CE continuation areas, reading them
/// through `read`. Loops and oversized areas are reported as corruption.
pub(crate) fn parse_with_continuations(
    area: &[u8],
    mut read: impl FnMut(Ce) -> Result<Vec<u8>, IsoError>,
) -> Result<RockRidge, IsoError> {
    let mut rr = RockRidge::default();
    let mut next = rr.parse_area(area);
    let mut hops = 0;
    while let Some(ce) = next {
        hops += 1;
        if hops > MAX_CONTINUATIONS || ce.len > MAX_CONTINUATION_LEN {
            return Err(IsoError::Corrupt("Rock Ridge continuation chain"));
        }
        let data = read(ce)?;
        next = rr.parse_area(&data);
    }
    Ok(rr)
}
```

Add `mod susp;` to `lib.rs`.

- [ ] **Step 4: Use Rock Ridge in the reader**

In `reader.rs`, add `use crate::susp::parse_with_continuations;`.

In `open`, after the root entry is built and before `Ok(Self { .. })`, detect SUSP in the root `.` record (only on the ISO9660 tree):
```rust
        let mut rock_ridge = false;
        let mut susp_skip = 0;
        if joliet_level == 0 && opts.rock_ridge {
            let first = read_bytes(&mut src, u64::from(root_record.lba) * BLOCK_SIZE as u64, BLOCK_SIZE)?;
            if let Some((dot, _)) = parse_record(&first)? {
                let rr = parse_with_continuations(&dot.system_use, |_| Ok(Vec::new()))?;
                if let Some(skip) = rr.sp_skip {
                    rock_ridge = true;
                    susp_skip = usize::from(skip);
                }
            }
        }
```
and use `rock_ridge, susp_skip,` in the returned struct.

Replace `make_entry` with:
```rust
    fn make_entry(&mut self, group: Group) -> Result<Option<Entry>, IsoError> {
        let mut entry = entry_from_record(&group.first, String::new());
        entry.size = group.size;
        entry.extents = group.extents;
        if !self.rock_ridge {
            entry.name = decode_name(&group.first.name, self.joliet_level);
            return Ok(Some(entry));
        }
        let area = &group.first.system_use[self.susp_skip.min(group.first.system_use.len())..];
        let src = &mut self.src;
        let rr = parse_with_continuations(area, |ce| {
            let offset = u64::from(ce.lba) * BLOCK_SIZE as u64 + u64::from(ce.offset);
            read_bytes(src, offset, ce.len as usize)
        })?;
        if rr.relocated {
            // The relocated directory itself; it is reached through its CL link.
            return Ok(None);
        }
        if let Some(lba) = rr.child_link {
            let block = read_bytes(&mut self.src, u64::from(lba) * BLOCK_SIZE as u64, BLOCK_SIZE)?;
            let (dot, _) = parse_record(&block)?.ok_or(IsoError::Corrupt("Rock Ridge child link"))?;
            entry.is_dir = true;
            entry.extents = vec![Extent { lba: dot.lba, len: dot.len }];
            entry.size = u64::from(dot.len);
            entry.relocated = true;
        }
        entry.name = match &rr.name {
            Some(n) if rr.present => String::from_utf8_lossy(n).into_owned(),
            _ => decode_name(&group.first.name, 0),
        };
        entry.rock_ridge = rr.present;
        entry.symlink = rr.symlink;
        entry.mode = rr.mode;
        Ok(Some(entry))
    }
```
Remove any `#[allow(dead_code)]` added for `susp_skip` in Task 7.

- [ ] **Step 5: Run the tests**

Run: `cargo test -p rufus-iso`
Expected: all tests pass, including `tests/rockridge.rs`.

- [ ] **Step 6: Commit**

```bash
git add crates/rufus-iso
git commit -m "feat(iso): SUSP and Rock Ridge (names, symlinks, modes, deep directories)"
```

---

### Task 10: `rufus-iso` — El Torito boot catalog

**Files:**
- Create: `crates/rufus-iso/src/eltorito.rs`
- Modify: `crates/rufus-iso/src/lib.rs`, `crates/rufus-iso/src/reader.rs`
- Test: unit tests in `eltorito.rs`; `crates/rufus-iso/tests/eltorito.rs`

**Interfaces:**
- Consumes: `IsoReader`, `read_bytes`, `boot_catalog_lba` (Task 7).
- Produces:
  - `pub struct BootEntry { pub platform: u8, pub bootable: bool, pub media_type: u8, pub load_segment: u16, pub system_type: u8, pub sector_count: u16, pub load_rba: u32 }`
  - `pub struct BootCatalog { pub id: String, pub entries: Vec<BootEntry> }`
  - `pub const PLATFORM_X86: u8 = 0`, `pub const PLATFORM_EFI: u8 = 0xEF`
  - `pub fn parse_boot_catalog(&[u8]) -> Result<BootCatalog, IsoError>`
  - `IsoReader::boot_catalog(&mut self) -> Result<Option<BootCatalog>, IsoError>`

- [ ] **Step 1: Write the failing tests**

`crates/rufus-iso/src/eltorito.rs` (tests):
```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn catalog() -> Vec<u8> {
        let mut c = vec![0u8; 2048];
        c[0] = 1; // validation entry
        c[1] = PLATFORM_X86;
        c[4..8].copy_from_slice(b"TEST");
        c[30] = 0x55;
        c[31] = 0xAA;
        let sum = c[..32]
            .chunks_exact(2)
            .fold(0u16, |s, w| s.wrapping_add(u16::from_le_bytes([w[0], w[1]])));
        c[28..30].copy_from_slice(&0u16.wrapping_sub(sum).to_le_bytes());
        // default entry
        c[32] = 0x88;
        c[38..40].copy_from_slice(&4u16.to_le_bytes());
        c[40..44].copy_from_slice(&35u32.to_le_bytes());
        // final section header: 1 EFI entry
        c[64] = 0x91;
        c[65] = PLATFORM_EFI;
        c[66..68].copy_from_slice(&1u16.to_le_bytes());
        c[96] = 0x88;
        c[102..104].copy_from_slice(&8u16.to_le_bytes());
        c[104..108].copy_from_slice(&36u32.to_le_bytes());
        c
    }

    #[test]
    fn parses_default_and_section_entries() {
        let cat = parse_boot_catalog(&catalog()).unwrap();
        assert_eq!(cat.id, "TEST");
        assert_eq!(cat.entries.len(), 2);
        assert_eq!((cat.entries[0].platform, cat.entries[0].sector_count, cat.entries[0].load_rba), (PLATFORM_X86, 4, 35));
        assert!(cat.entries[0].bootable);
        assert_eq!((cat.entries[1].platform, cat.entries[1].sector_count, cat.entries[1].load_rba), (PLATFORM_EFI, 8, 36));
    }

    #[test]
    fn bad_checksum_or_signature_is_corrupt() {
        let mut c = catalog();
        c[5] ^= 1;
        assert!(matches!(parse_boot_catalog(&c), Err(IsoError::Corrupt(_))));
        let mut c = catalog();
        c[31] = 0;
        assert!(matches!(parse_boot_catalog(&c), Err(IsoError::Corrupt(_))));
        assert!(matches!(parse_boot_catalog(&[0u8; 10]), Err(IsoError::Corrupt(_))));
    }
}
```

`crates/rufus-iso/tests/eltorito.rs`:
```rust
mod common;

use common::*;
use rufus_iso::{IsoOptions, IsoReader, PLATFORM_EFI, PLATFORM_X86};

#[test]
fn reads_bios_and_efi_boot_entries() {
    let mut iso = IsoReader::open(fixture("eltorito.iso"), IsoOptions::default()).unwrap();
    let cat = iso.boot_catalog().unwrap().expect("El Torito catalog");
    assert_eq!(cat.entries.len(), 2);
    let bios = iso.lookup("/boot/bios.img").unwrap().unwrap();
    let efi = iso.lookup("/boot/efi.img").unwrap().unwrap();
    assert_eq!(cat.entries[0].platform, PLATFORM_X86);
    assert!(cat.entries[0].bootable);
    assert_eq!(cat.entries[0].sector_count, 4);
    assert_eq!(cat.entries[0].load_rba, bios.extents[0].lba);
    assert_eq!(cat.entries[1].platform, PLATFORM_EFI);
    assert_eq!(cat.entries[1].load_rba, efi.extents[0].lba);
}

#[test]
fn plain_iso_has_no_catalog() {
    let mut iso = IsoReader::open(fixture("plain.iso"), IsoOptions::default()).unwrap();
    assert!(iso.boot_catalog().unwrap().is_none());
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p rufus-iso`
Expected: compile errors (`parse_boot_catalog`, `boot_catalog` undefined).

- [ ] **Step 3: Implement `eltorito.rs`**

Above the tests:
```rust
use crate::IsoError;
use crate::bytes::{le16, le32};

pub const PLATFORM_X86: u8 = 0x00;
pub const PLATFORM_EFI: u8 = 0xEF;
const MAX_ENTRIES: usize = 64;

/// One bootable image described by the catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootEntry {
    pub platform: u8,
    pub bootable: bool,
    pub media_type: u8,
    pub load_segment: u16,
    pub system_type: u8,
    /// Number of 512-byte virtual sectors to load.
    pub sector_count: u16,
    pub load_rba: u32,
}

/// An El Torito boot catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootCatalog {
    pub id: String,
    pub entries: Vec<BootEntry>,
}

fn boot_entry(e: &[u8], platform: u8) -> BootEntry {
    BootEntry {
        platform,
        bootable: e[0] == 0x88,
        media_type: e[1],
        load_segment: le16(&e[2..4]),
        system_type: e[4],
        sector_count: le16(&e[6..8]),
        load_rba: le32(&e[8..12]),
    }
}

/// Parses the first block of a boot catalog.
pub fn parse_boot_catalog(b: &[u8]) -> Result<BootCatalog, IsoError> {
    if b.len() < 64 || b[0] != 1 || b[30] != 0x55 || b[31] != 0xAA {
        return Err(IsoError::Corrupt("El Torito validation entry"));
    }
    let sum = b[..32]
        .chunks_exact(2)
        .fold(0u16, |s, w| s.wrapping_add(u16::from_le_bytes([w[0], w[1]])));
    if sum != 0 {
        return Err(IsoError::Corrupt("El Torito validation checksum"));
    }
    let id = String::from_utf8_lossy(&b[4..28]).trim_end_matches(['\0', ' ']).to_string();
    let mut entries = vec![boot_entry(&b[32..64], b[1])];
    let mut pos = 64;
    while pos + 32 <= b.len() && entries.len() < MAX_ENTRIES {
        let header = b[pos];
        if header != 0x90 && header != 0x91 {
            break;
        }
        let platform = b[pos + 1];
        let count = usize::from(le16(&b[pos + 2..pos + 4]));
        pos += 32;
        for _ in 0..count {
            if pos + 32 > b.len() || entries.len() >= MAX_ENTRIES {
                break;
            }
            entries.push(boot_entry(&b[pos..pos + 32], platform));
            pos += 32;
        }
        if header == 0x91 {
            break;
        }
    }
    Ok(BootCatalog { id, entries })
}
```

In `lib.rs`: add `mod eltorito;` and `pub use eltorito::{BootCatalog, BootEntry, PLATFORM_EFI, PLATFORM_X86, parse_boot_catalog};`.

In `reader.rs`, add `use crate::eltorito::{BootCatalog, parse_boot_catalog};` and this method to the `impl`:
```rust
    /// The El Torito boot catalog, if the image has one.
    pub fn boot_catalog(&mut self) -> Result<Option<BootCatalog>, IsoError> {
        let Some(lba) = self.boot_catalog_lba else { return Ok(None) };
        let block = read_bytes(&mut self.src, u64::from(lba) * BLOCK_SIZE as u64, BLOCK_SIZE)?;
        parse_boot_catalog(&block).map(Some)
    }
```
Remove any `#[allow(dead_code)]` added for `boot_catalog_lba` in Task 7.

- [ ] **Step 4: Run the tests**

Run: `cargo test -p rufus-iso`
Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/rufus-iso
git commit -m "feat(iso): El Torito boot catalog"
```

---

### Task 11: `rufus-hash` — MD5 / SHA-1 / SHA-256 / SHA-512

**Files:**
- Create: `crates/rufus-hash/Cargo.toml`, `crates/rufus-hash/src/lib.rs`
- Modify: `Cargo.toml` (members, workspace deps)
- Test: unit tests in `lib.rs`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `pub struct Hashes { pub md5: String, pub sha1: String, pub sha256: String, pub sha512: String }` (lowercase hex) with `log_lines(&self) -> Vec<String>` (upstream log format)
  - `pub struct MultiHasher` with `new()`, `update(&mut self, &[u8])`, `finalize(self) -> Hashes`
  - `pub fn hash_reader<R: Read>(reader: R, cancel: &AtomicBool, progress: impl FnMut(u64)) -> io::Result<Hashes>`; cancellation returns `io::ErrorKind::Interrupted`

- [ ] **Step 1: Create the crate**

Root `Cargo.toml`: add `"crates/rufus-hash"` to `members`; add to `[workspace.dependencies]`:
```toml
rufus-hash = { path = "crates/rufus-hash" }
md-5 = "0.11"
sha1 = "0.11"
sha2 = "0.11"
hex = "0.4"
```

`crates/rufus-hash/Cargo.toml`:
```toml
[package]
name = "rufus-hash"
description = "Parallel MD5/SHA-1/SHA-256/SHA-512 hashing for rufus-rs"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true

[dependencies]
md-5.workspace = true
sha1.workspace = true
sha2.workspace = true
hex.workspace = true

[lints]
workspace = true
```

- [ ] **Step 2: Write the failing tests**

`crates/rufus-hash/src/lib.rs`:
```rust
//! MD5, SHA-1, SHA-256 and SHA-512 computed together, like Rufus's hash dialog.

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::atomic::AtomicBool;

    #[test]
    fn known_vectors() {
        let mut h = MultiHasher::new();
        h.update(b"abc");
        let r = h.finalize();
        assert_eq!(r.md5, "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(r.sha1, "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(r.sha256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(
            r.sha512,
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    #[test]
    fn empty_input() {
        let r = MultiHasher::new().finalize();
        assert_eq!(r.md5, "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(r.sha256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn chunked_reader_matches_single_update() {
        let data: Vec<u8> = (0..10_000_000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8).collect();
        let mut single = MultiHasher::new();
        single.update(&data);
        let mut seen = 0;
        let streamed = hash_reader(Cursor::new(&data), &AtomicBool::new(false), |n| seen = n).unwrap();
        assert_eq!(streamed, single.finalize());
        assert_eq!(seen, data.len() as u64);
    }

    #[test]
    fn cancellation() {
        let err = hash_reader(Cursor::new(vec![0u8; 1024]), &AtomicBool::new(true), |_| {}).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Interrupted);
    }

    #[test]
    fn log_lines_match_upstream_format() {
        let mut h = MultiHasher::new();
        h.update(b"abc");
        let lines = h.finalize().log_lines();
        assert_eq!(lines[0], "  MD5:    900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(lines[1], "  SHA1:   a9993e364706816aba3e25717850c26c9cd0d89d");
        assert!(lines[2].starts_with("  SHA256: ba7816bf"));
        assert_eq!(lines[3], "  SHA512: ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a");
        assert_eq!(lines[4], "          2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    }
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test -p rufus-hash`
Expected: compile errors (`MultiHasher` undefined).

- [ ] **Step 4: Implement**

Above the tests in `crates/rufus-hash/src/lib.rs`:
```rust
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use std::io::{self, Read};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

const BUFFER_SIZE: usize = 4 << 20;
const PARALLEL_THRESHOLD: usize = 64 << 10;

/// Lowercase hexadecimal digests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hashes {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub sha512: String,
}

impl Hashes {
    /// The lines upstream writes to its log; SHA-512 is split over two lines.
    /// upstream: hash.c HashThread @942ed3a4
    pub fn log_lines(&self) -> Vec<String> {
        let (a, b) = self.sha512.split_at(self.sha512.len() / 2);
        vec![
            format!("  MD5:    {}", self.md5),
            format!("  SHA1:   {}", self.sha1),
            format!("  SHA256: {}", self.sha256),
            format!("  SHA512: {a}"),
            format!("          {b}"),
        ]
    }
}

/// Feeds the same data to all four hash functions, on four threads for large buffers.
#[derive(Debug, Clone, Default)]
pub struct MultiHasher {
    md5: Md5,
    sha1: Sha1,
    sha256: Sha256,
    sha512: Sha512,
}

impl MultiHasher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update(&mut self, data: &[u8]) {
        let MultiHasher { md5, sha1, sha256, sha512 } = self;
        if data.len() < PARALLEL_THRESHOLD {
            md5.update(data);
            sha1.update(data);
            sha256.update(data);
            sha512.update(data);
            return;
        }
        thread::scope(|s| {
            s.spawn(|| md5.update(data));
            s.spawn(|| sha1.update(data));
            s.spawn(|| sha256.update(data));
            sha512.update(data);
        });
    }

    pub fn finalize(self) -> Hashes {
        Hashes {
            md5: hex::encode(self.md5.finalize()),
            sha1: hex::encode(self.sha1.finalize()),
            sha256: hex::encode(self.sha256.finalize()),
            sha512: hex::encode(self.sha512.finalize()),
        }
    }
}

/// Hashes everything `reader` yields. `progress` receives the running byte count.
pub fn hash_reader<R: Read>(mut reader: R, cancel: &AtomicBool, mut progress: impl FnMut(u64)) -> io::Result<Hashes> {
    let mut hasher = MultiHasher::new();
    let mut buf = vec![0u8; BUFFER_SIZE];
    let mut total = 0u64;
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "hashing cancelled"));
        }
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        hasher.update(&buf[..n]);
        total += n as u64;
        progress(total);
    }
    Ok(hasher.finalize())
}
```
If `Md5`/`Sha1`/`Sha256`/`Sha512` do not implement `Default` or `Debug` in digest 0.11 (drop `Debug` from the derive and implement it by hand, printing `MultiHasher { .. }`, if only `Debug` is missing), replace `#[derive(Default)]` with a manual `impl Default for MultiHasher` that calls `Md5::new()` and so on (check with Context7 `/rustcrypto/hashes` if it fails to compile).

- [ ] **Step 5: Run the tests**

Run: `cargo test -p rufus-hash`
Expected: 5 tests pass.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml crates/rufus-hash
git commit -m "feat(hash): parallel MD5/SHA-1/SHA-256/SHA-512 with upstream log format"
```

---

### Task 12: `xtask data-sync` and `rufus-l10n`

**Files:**
- Create: `xtask/Cargo.toml`, `xtask/src/main.rs`, `.cargo/config.toml`
- Create: `data/loc/rufus.loc`, `data/UPSTREAM` (generated by the xtask)
- Create: `crates/rufus-l10n/Cargo.toml`, `crates/rufus-l10n/src/{lib.rs,parse.rs,printf.rs,size.rs}`
- Modify: `Cargo.toml` (members, workspace deps)
- Test: unit tests in `parse.rs`, `printf.rs`, `size.rs`; `crates/rufus-l10n/tests/embedded.rs`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `cargo xtask data-sync --upstream <pbatard/rufus checkout>` copies `res/loc/rufus.loc` to `data/loc/rufus.loc` and writes the checkout's commit to `data/UPSTREAM`
  - `pub fn parse(&str) -> Result<LocFile, LocError>`; `pub struct LocFile { pub locales: Vec<Locale> }`; `pub struct Locale { pub code, pub name, pub lcids: Vec<u32>, pub version: Vec<u32>, pub base: Option<String>, pub rtl: bool, pub messages: BTreeMap<u16, String>, pub dialogs: BTreeMap<String, BTreeMap<String, String>> }`; `pub struct LocError { pub line: usize, pub msg: String }`
  - `LocFile::locale(&self, code) -> Option<&Locale>`, `LocFile::catalog(&self, code) -> Option<Catalog<'_>>`
  - `Catalog::{code, is_rtl, msg(u16) -> String, control(group, ctrl) -> Option<&str>, fmt(u16, &[Arg]) -> String}`
  - `pub fn embedded() -> &'static LocFile`
  - `pub enum Arg<'a> { Str(&'a str), Int(i64), UInt(u64), Float(f64), Char(char) }`, `pub fn sprintf(&str, &[Arg]) -> String`
  - `pub fn size_to_human_readable(size: u64, cat: &Catalog<'_>, fake_units: bool, rtl_marks: bool) -> String`

Parity notes for the implementer:
- The line assembler ports upstream `parser.c get_loc_data_file` exactly: `\n` (escape) becomes a newline (LF, not CRLF), `\"` becomes `"`, `\\` becomes `\`, other escapes are dropped, an escaped line end joins lines, and a string ending in `"` followed by a line starting with `"` is concatenated.
- `f` (font) commands are parsed for validation but ignored: they are Win32 dialog fonts.
- `MSG_` texts go into `messages` whatever the current group, as upstream does.

- [ ] **Step 1: Create the xtask and sync the data**

Root `Cargo.toml`: add `"xtask"` and `"crates/rufus-l10n"` to `members`; add `rufus-l10n = { path = "crates/rufus-l10n" }` to `[workspace.dependencies]`.

`.cargo/config.toml`:
```toml
[alias]
xtask = "run --package xtask --"
```

`xtask/Cargo.toml`:
```toml
[package]
name = "xtask"
version = "0.0.0"
edition.workspace = true
license.workspace = true
publish = false

[lints]
workspace = true
```

`xtask/src/main.rs`:
```rust
//! Repository maintenance tasks: `cargo xtask <command>`.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::{env, fs};

/// Upstream data files reused as-is: (path in pbatard/rufus, path in this repo).
const DATA_FILES: &[(&str, &str)] = &[("res/loc/rufus.loc", "data/loc/rufus.loc")];

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let result = match args.as_slice() {
        [cmd, flag, path] if cmd == "data-sync" && flag == "--upstream" => data_sync(Path::new(path)),
        _ => Err("usage: cargo xtask data-sync --upstream <path to a pbatard/rufus checkout>".to_string()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("xtask: {e}");
            ExitCode::FAILURE
        }
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().expect("xtask lives in the workspace").to_path_buf()
}

fn data_sync(upstream: &Path) -> Result<(), String> {
    let rev = Command::new("git")
        .arg("-C")
        .arg(upstream)
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|e| format!("git: {e}"))?;
    if !rev.status.success() {
        return Err(format!("{} is not a git checkout", upstream.display()));
    }
    let rev = String::from_utf8_lossy(&rev.stdout).trim().to_string();
    let root = workspace_root();
    for (src, dst) in DATA_FILES {
        let to = root.join(dst);
        fs::create_dir_all(to.parent().expect("data file has a parent")).map_err(|e| format!("{dst}: {e}"))?;
        fs::copy(upstream.join(src), &to).map_err(|e| format!("{src}: {e}"))?;
        println!("synced {src} -> {dst}");
    }
    fs::write(root.join("data/UPSTREAM"), format!("{rev}\n")).map_err(|e| format!("data/UPSTREAM: {e}"))?;
    println!("upstream revision {rev}");
    Ok(())
}
```

Create a pristine upstream checkout at the baseline (a worktree of the existing reference repo, no download needed) and sync:
```bash
git -C ~/Code/rufusLinux worktree add ~/Code/rufus-upstream 942ed3a4
cargo xtask data-sync --upstream ~/Code/rufus-upstream
```
Expected: `synced res/loc/rufus.loc -> data/loc/rufus.loc` and `upstream revision 942ed3a4…`.

- [ ] **Step 2: Write the failing tests**

`crates/rufus-l10n/Cargo.toml`:
```toml
[package]
name = "rufus-l10n"
description = "Rufus translation file (rufus.loc) parser and message formatting"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true

[dependencies]
thiserror.workspace = true

[lints]
workspace = true
```

`crates/rufus-l10n/src/parse.rs` (tests):
```rust
#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
# comment
l "en-US" "English (English)" 0x0409, 0x0809
v 4.14

g IDD_DIALOG
t IDC_SELECT "Select"
t MSG_001 "Other instance detected"
t MSG_002 "Line one.\n"
	"Line two with \"quotes\" and a \\ backslash"
t MSG_003 "joined \
continued"

l "xx-XX" "Test" 0x0001
v 4.14
b "en-US"
a "r"
g IDD_DIALOG
t IDC_SELECT "Choose"
"#;

    #[test]
    fn parses_locales_groups_and_messages() {
        let f = parse(SAMPLE).unwrap();
        assert_eq!(f.locales.len(), 2);
        let en = &f.locales[0];
        assert_eq!(en.code, "en-US");
        assert_eq!(en.name, "English (English)");
        assert_eq!(en.lcids, vec![0x0409, 0x0809]);
        assert_eq!(en.version, vec![4, 14]);
        assert_eq!(en.dialogs["IDD_DIALOG"]["IDC_SELECT"], "Select");
        assert_eq!(en.messages[&1], "Other instance detected");
        assert_eq!(en.messages[&2], "Line one.\nLine two with \"quotes\" and a \\ backslash");
        assert_eq!(en.messages[&3], "joined continued");
        let xx = &f.locales[1];
        assert_eq!(xx.base.as_deref(), Some("en-US"));
        assert!(xx.rtl);
    }

    #[test]
    fn syntax_errors_report_the_line() {
        let err = parse("l \"en-US\" \"x\" 1\nt IDC_X \"unterminated\n").unwrap_err();
        assert_eq!(err.line, 2);
        assert!(parse("t IDC_X \"before any locale\"").is_err());
        assert!(parse("l \"a\" \"b\" 1\nz nope").is_err());
    }
}
```

`crates/rufus-l10n/src/printf.rs` (tests):
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_the_specifiers_used_by_rufus_loc() {
        let s = sprintf(
            "%s has %d items (%02X) %0.2f%% %c|%5s|%-4d|%S|%02d",
            &[
                Arg::Str("disk"),
                Arg::Int(3),
                Arg::UInt(10),
                Arg::Float(1.5),
                Arg::Char('x'),
                Arg::Str("ab"),
                Arg::Int(7),
                Arg::Str("wide"),
                Arg::Int(-5),
            ],
        );
        assert_eq!(s, "disk has 3 items (0A) 1.50% x|   ab|7   |wide|-5");
    }

    #[test]
    fn missing_arguments_are_empty() {
        assert_eq!(sprintf("a%sb%dc", &[]), "abc");
        assert_eq!(sprintf("100%", &[]), "100%");
    }
}
```

`crates/rufus-l10n/src/size.rs` (tests):
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::embedded;

    #[test]
    fn matches_upstream_formatting() {
        let en = embedded().catalog("en-US").unwrap();
        let h = |size, fake| size_to_human_readable(size, &en, fake, false);
        assert_eq!(h(512, false), "512 bytes");
        assert_eq!(h(1023, false), "1023 bytes");
        assert_eq!(h(1536, false), "1.5 KB");
        assert_eq!(h(8 << 30, false), "8 GB");
        assert_eq!(h(8_480_000_000, false), "7.9 GB");
        assert_eq!(h(1_048_575, false), "1024.0 KB");
        assert_eq!(h(16_000_000_000, true), "16 GB");
        assert_eq!(h(15_500_000_000, true), "16 GB");
        assert_eq!(h(7_500_000_000, true), "7.5GB");
        assert_eq!(h(7_000_000_000, true), "7GB");
        assert_eq!(h(1 << 50, false), "1 PB");
        assert_eq!(h(3 << 60, false), "3072 PB");
    }

    #[test]
    fn rtl_marks_wrap_the_number() {
        let en = embedded().catalog("en-US").unwrap();
        assert_eq!(size_to_human_readable(8 << 30, &en, false, true), "\u{200E}8\u{200E} GB");
    }
}
```

`crates/rufus-l10n/tests/embedded.rs`:
```rust
use rufus_l10n::embedded;

#[test]
fn embedded_file_parses_with_all_locales() {
    let f = embedded();
    assert_eq!(f.locales.len(), 38);
    assert_eq!(f.locales[0].code, "en-US");
    assert_eq!(f.locales.iter().filter(|l| l.rtl).count(), 3);
    for code in ["ar-SA", "he-IL", "fa-IR"] {
        assert!(f.locale(code).unwrap().rtl, "{code}");
    }
}

#[test]
fn english_messages_and_controls() {
    let en = embedded().catalog("en-US").unwrap();
    assert_eq!(en.msg(1), "Other instance detected");
    assert_eq!(
        en.msg(2),
        "Another Rufus application is running.\nPlease close the first application before running another one."
    );
    assert!(en.msg(162).contains("the \"slow\" format"));
    assert_eq!(en.control("IDD_DIALOG", "IDC_SELECT"), Some("Select"));
    assert_eq!(en.msg(3999), "(default) MSG_3999 UNTRANSLATED");
}

#[test]
fn translations_fall_back_to_the_base_locale() {
    let de = embedded().catalog("de-DE").unwrap();
    assert!(!de.is_rtl());
    assert_ne!(de.msg(1), embedded().catalog("en-US").unwrap().msg(1));
    let ar = embedded().catalog("ar-SA").unwrap();
    assert!(ar.is_rtl());
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test -p rufus-l10n`
Expected: compile errors (`parse`, `sprintf`, `embedded` undefined).

- [ ] **Step 4: Implement `parse.rs`**

Above the tests:
```rust
use std::collections::BTreeMap;

/// One translation (`l` section) of `rufus.loc`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Locale {
    pub code: String,
    pub name: String,
    pub lcids: Vec<u32>,
    pub version: Vec<u32>,
    pub base: Option<String>,
    pub rtl: bool,
    pub messages: BTreeMap<u16, String>,
    pub dialogs: BTreeMap<String, BTreeMap<String, String>>,
}

/// A parsed `rufus.loc` file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LocFile {
    pub locales: Vec<Locale>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("rufus.loc line {line}: {msg}")]
pub struct LocError {
    pub line: usize,
    pub msg: String,
}

fn err(line: usize, msg: impl Into<String>) -> LocError {
    LocError { line, msg: msg.into() }
}

/// Splits the file into logical command lines.
/// upstream: parser.c get_loc_data_file @942ed3a4
fn logical_lines(src: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut line_no = 1;
    let mut start_line = 1;
    let mut eol = false;
    let mut escape = false;
    for c in src.chars() {
        match c {
            '\r' | '\n' => {
                if c == '\n' {
                    line_no += 1;
                }
                if escape {
                    escape = false;
                    continue;
                }
                if !eol {
                    let trimmed = buf.trim_end_matches([' ', '\t']).len();
                    buf.truncate(trimmed);
                    eol = true;
                }
            }
            ' ' | '\t' => {
                if escape {
                    escape = false;
                    continue;
                }
                if !eol {
                    buf.push(c);
                }
            }
            '\\' if !escape => escape = true,
            _ => {
                if escape {
                    match c {
                        'n' => buf.push('\n'),
                        '"' => buf.push_str("\\\""),
                        '\\' => buf.push('\\'),
                        _ => {}
                    }
                    escape = false;
                    continue;
                }
                if eol && c == '"' && buf.ends_with('"') {
                    // A string continued on the next line: drop both quotes.
                    buf.pop();
                    eol = false;
                    continue;
                }
                if eol {
                    out.push((start_line, std::mem::take(&mut buf)));
                    eol = false;
                    start_line = line_no;
                }
                buf.push(c);
            }
        }
    }
    if !buf.is_empty() {
        out.push((start_line, buf));
    }
    out
}

fn parse_c_uint(t: &str) -> Option<u32> {
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else if t.len() > 1 && t.starts_with('0') {
        u32::from_str_radix(&t[1..], 8).ok()
    } else {
        t.parse().ok()
    }
}

struct Args<'a> {
    s: &'a str,
    line: usize,
}

impl Args<'_> {
    fn skip_ws(&mut self) {
        self.s = self.s.trim_start_matches([' ', '\t']);
    }

    /// A quoted string; `\"` inside it becomes `"`.
    fn string(&mut self) -> Result<String, LocError> {
        self.skip_ws();
        let body = self.s.strip_prefix('"').ok_or_else(|| err(self.line, "no start quote"))?;
        let mut out = String::new();
        let mut prev_backslash = false;
        for (i, c) in body.char_indices() {
            if c == '"' {
                if prev_backslash {
                    out.pop();
                    out.push('"');
                    prev_backslash = false;
                    continue;
                }
                self.s = &body[i + 1..];
                return Ok(out);
            }
            out.push(c);
            prev_backslash = c == '\\';
        }
        Err(err(self.line, "no end quote"))
    }

    /// A single word (control ID).
    fn word(&mut self) -> Result<String, LocError> {
        self.skip_ws();
        let end = self.s.find([' ', '\t']).unwrap_or(self.s.len());
        if end == 0 {
            return Err(err(self.line, "missing parameter"));
        }
        let w = self.s[..end].to_string();
        self.s = &self.s[end..];
        Ok(w)
    }

    /// A comma- or dot-separated list of integers up to the end of the line.
    fn uint_list(&mut self) -> Result<Vec<u32>, LocError> {
        self.skip_ws();
        let line = self.line;
        let list = self
            .s
            .split([',', '.'])
            .map(|t| parse_c_uint(t.trim()).ok_or_else(|| err(line, format!("invalid number '{t}'"))))
            .collect();
        self.s = "";
        list
    }

    fn int(&mut self) -> Result<i64, LocError> {
        let w = self.word()?;
        let (neg, digits) = match w.strip_prefix('-') {
            Some(d) => (true, d),
            None => (false, w.as_str()),
        };
        let v = parse_c_uint(digits).ok_or_else(|| err(self.line, format!("invalid integer '{w}'")))?;
        Ok(if neg { -i64::from(v) } else { i64::from(v) })
    }
}

/// Parses a `rufus.loc` file.
/// upstream: parser.c get_loc_cmd / get_loc_data_line @942ed3a4
pub fn parse(src: &str) -> Result<LocFile, LocError> {
    let mut file = LocFile::default();
    let mut group = String::new();
    for (line_no, raw) in logical_lines(src) {
        let line = raw.trim_start_matches([' ', '\t']);
        let mut chars = line.chars();
        let Some(cmd) = chars.next() else { continue };
        if cmd == '#' {
            continue;
        }
        let rest = chars.as_str();
        if !rest.starts_with([' ', '\t']) {
            return Err(err(line_no, format!("syntax error: '{line}'")));
        }
        let mut a = Args { s: rest, line: line_no };
        if cmd == 'l' {
            let code = a.string()?;
            let name = a.string()?;
            let lcids = a.uint_list()?;
            file.locales.push(Locale { code, name, lcids, ..Default::default() });
            group.clear();
            continue;
        }
        let locale = file
            .locales
            .last_mut()
            .ok_or_else(|| err(line_no, "command before any 'l' locale"))?;
        match cmd {
            'v' => locale.version = a.uint_list()?,
            'b' => locale.base = Some(a.string()?),
            'a' => locale.rtl = a.string()?.contains('r'),
            'g' => group = a.word()?,
            't' => {
                let control = a.word()?;
                let text = a.string()?;
                if let Some(n) = control.strip_prefix("MSG_") {
                    let id = n.parse().map_err(|_| err(line_no, format!("invalid message id '{control}'")))?;
                    locale.messages.insert(id, text);
                } else {
                    locale.dialogs.entry(group.clone()).or_default().insert(control, text);
                }
            }
            'f' => {
                // Win32 dialog fonts: validated, not used.
                a.string()?;
                a.int()?;
            }
            _ => return Err(err(line_no, format!("unknown command '{cmd}'"))),
        }
    }
    Ok(file)
}
```

- [ ] **Step 5: Implement `printf.rs`**

Above the tests:
```rust
/// An argument for [`sprintf`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Arg<'a> {
    Str(&'a str),
    Int(i64),
    UInt(u64),
    Float(f64),
    Char(char),
}

impl Arg<'_> {
    fn as_i64(&self) -> i64 {
        match *self {
            Arg::Int(v) => v,
            Arg::UInt(v) => v as i64,
            Arg::Float(v) => v as i64,
            Arg::Char(c) => i64::from(u32::from(c)),
            Arg::Str(s) => s.parse().unwrap_or(0),
        }
    }

    fn as_f64(&self) -> f64 {
        match *self {
            Arg::Float(v) => v,
            Arg::Int(v) => v as f64,
            Arg::UInt(v) => v as f64,
            Arg::Char(c) => f64::from(u32::from(c)),
            Arg::Str(s) => s.parse().unwrap_or(0.0),
        }
    }

    fn to_text(self) -> String {
        match self {
            Arg::Str(s) => s.to_string(),
            Arg::Int(v) => v.to_string(),
            Arg::UInt(v) => v.to_string(),
            Arg::Float(v) => v.to_string(),
            Arg::Char(c) => c.to_string(),
        }
    }
}

fn pad(out: &mut String, body: &str, width: usize, left: bool, zero: bool) {
    let len = body.chars().count();
    if len >= width {
        out.push_str(body);
        return;
    }
    let fill = width - len;
    if left {
        out.push_str(body);
        out.extend(std::iter::repeat_n(' ', fill));
    } else if zero {
        let (sign, digits) = match body.strip_prefix('-') {
            Some(d) => ("-", d),
            None => ("", body),
        };
        out.push_str(sign);
        out.extend(std::iter::repeat_n('0', fill));
        out.push_str(digits);
    } else {
        out.extend(std::iter::repeat_n(' ', fill));
        out.push_str(body);
    }
}

/// The printf subset used by `rufus.loc`: `%s %S %d %i %u %x %X %c %f %%`
/// with flags `-` and `0`, a width, a precision and ignored length modifiers.
pub fn sprintf(fmt: &str, args: &[Arg<'_>]) -> String {
    let mut out = String::with_capacity(fmt.len() + 16);
    let mut args = args.iter().copied();
    let mut chars = fmt.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        let (mut left, mut zero) = (false, false);
        while let Some(&f) = chars.peek() {
            match f {
                '-' => left = true,
                '0' => zero = true,
                '+' | ' ' | '#' => {}
                _ => break,
            }
            chars.next();
        }
        let mut width = 0usize;
        while let Some(d) = chars.peek().and_then(|c| c.to_digit(10)) {
            width = width * 10 + d as usize;
            chars.next();
        }
        let mut precision = None;
        if chars.peek() == Some(&'.') {
            chars.next();
            let mut p = 0usize;
            while let Some(d) = chars.peek().and_then(|c| c.to_digit(10)) {
                p = p * 10 + d as usize;
                chars.next();
            }
            precision = Some(p);
        }
        while matches!(chars.peek(), Some('h' | 'l' | 'z' | 'j' | 't')) {
            chars.next();
        }
        if chars.peek() == Some(&'I') {
            chars.next();
            if chars.peek() == Some(&'6') || chars.peek() == Some(&'3') {
                chars.next();
                chars.next();
            }
        }
        let Some(conv) = chars.next() else {
            out.push('%');
            break;
        };
        let body = match conv {
            '%' => {
                out.push('%');
                continue;
            }
            's' | 'S' => args.next().map(Arg::to_text).unwrap_or_default(),
            'd' | 'i' => args.next().map(|a| a.as_i64().to_string()).unwrap_or_default(),
            'u' => args.next().map(|a| (a.as_i64() as u64).to_string()).unwrap_or_default(),
            'x' => args.next().map(|a| format!("{:x}", a.as_i64() as u64)).unwrap_or_default(),
            'X' => args.next().map(|a| format!("{:X}", a.as_i64() as u64)).unwrap_or_default(),
            'c' => args
                .next()
                .map(|a| match a {
                    Arg::Char(c) => c.to_string(),
                    other => char::from_u32(other.as_i64() as u32).map(String::from).unwrap_or_default(),
                })
                .unwrap_or_default(),
            'f' => args
                .next()
                .map(|a| format!("{:.*}", precision.unwrap_or(6), a.as_f64()))
                .unwrap_or_default(),
            other => {
                out.push('%');
                out.push(other);
                continue;
            }
        };
        let numeric = !matches!(conv, 's' | 'S' | 'c');
        pad(&mut out, &body, width, left, zero && !left && numeric);
    }
    out
}
```

- [ ] **Step 6: Implement `size.rs` and `lib.rs`**

`crates/rufus-l10n/src/size.rs` (above the tests):
```rust
use crate::Catalog;

const MSG_SIZE_BYTES: u16 = 20; // MSG_020..MSG_025: bytes, KB, MB, GB, TB, PB
const MAX_SIZE_SUFFIXES: u16 = 6;
const LEFT_TO_RIGHT_MARK: &str = "\u{200E}";

/// upstream: stdio.c upo2 @942ed3a4
fn upo2(v: u16) -> u16 {
    v.checked_next_power_of_two().unwrap_or(0)
}

/// Human-readable size with localised units. `fake_units` uses powers of
/// 1000 and rounds to "marketing" sizes; `rtl_marks` wraps the number in
/// left-to-right marks for right-to-left UIs.
/// upstream: stdio.c SizeToHumanReadable @942ed3a4
pub fn size_to_human_readable(size: u64, cat: &Catalog<'_>, fake_units: bool, rtl_marks: bool) -> String {
    let dir = if rtl_marks { LEFT_TO_RIGHT_MARK } else { "" };
    let divider = if fake_units { 1000.0 } else { 1024.0 };
    let mut hr = size as f64;
    let mut suffix = 0u16;
    while suffix < MAX_SIZE_SUFFIXES - 1 {
        if hr < divider {
            break;
        }
        hr /= divider;
        suffix += 1;
    }
    let unit = cat.msg(MSG_SIZE_BYTES + suffix);
    if suffix == 0 {
        format!("{dir}{}{dir} {unit}", hr as i64)
    } else if fake_units {
        if hr < 8.0 {
            if ((hr * 10.0) - ((hr + 0.5).floor() * 10.0)).abs() < 0.5 {
                format!("{hr:.0}{unit}")
            } else {
                format!("{hr:.1}{unit}")
            }
        } else {
            let t = f64::from(upo2(hr as u16));
            let i = if (1.0 - hr / t).abs() < 0.05 { t as u16 } else { hr as u16 };
            format!("{dir}{i}{dir} {unit}")
        }
    } else if hr * 10.0 - hr.floor() * 10.0 < 0.5 {
        format!("{dir}{hr:.0}{dir} {unit}")
    } else {
        format!("{dir}{hr:.1}{dir} {unit}")
    }
}
```

`crates/rufus-l10n/src/lib.rs`:
```rust
//! Rufus's translation file (`rufus.loc`) and message formatting.

mod parse;
mod printf;
mod size;

use std::sync::OnceLock;

pub use parse::{LocError, LocFile, Locale, parse};
pub use printf::{Arg, sprintf};
pub use size::size_to_human_readable;

/// The upstream translation file, synced by `cargo xtask data-sync`.
pub const EMBEDDED_LOC: &str = include_str!("../../../data/loc/rufus.loc");

/// The parsed embedded translation file.
pub fn embedded() -> &'static LocFile {
    static FILE: OnceLock<LocFile> = OnceLock::new();
    FILE.get_or_init(|| parse(EMBEDDED_LOC).expect("the embedded rufus.loc is valid"))
}

/// Message lookup for one locale, falling back to its base and then to the
/// first locale in the file (en-US), as upstream does.
#[derive(Debug, Clone, Copy)]
pub struct Catalog<'a> {
    locale: &'a Locale,
    base: Option<&'a Locale>,
    default: &'a Locale,
}

impl LocFile {
    pub fn locale(&self, code: &str) -> Option<&Locale> {
        self.locales.iter().find(|l| l.code == code)
    }

    pub fn catalog(&self, code: &str) -> Option<Catalog<'_>> {
        let locale = self.locale(code)?;
        let default = self.locales.first()?;
        let base = locale.base.as_deref().and_then(|b| self.locale(b));
        Some(Catalog { locale, base, default })
    }
}

impl<'a> Catalog<'a> {
    fn chain(&self) -> impl Iterator<Item = &'a Locale> {
        [Some(self.locale), self.base, Some(self.default)].into_iter().flatten()
    }

    pub fn code(&self) -> &'a str {
        &self.locale.code
    }

    pub fn is_rtl(&self) -> bool {
        self.locale.rtl
    }

    /// The text of `MSG_<id>`.
    pub fn msg(&self, id: u16) -> String {
        self.chain()
            .find_map(|l| l.messages.get(&id).cloned())
            .unwrap_or_else(|| format!("(default) MSG_{id:03} UNTRANSLATED"))
    }

    /// The text for a dialog control, e.g. `("IDD_DIALOG", "IDC_SELECT")`.
    pub fn control(&self, group: &str, control: &str) -> Option<&'a str> {
        self.chain()
            .find_map(|l| l.dialogs.get(group).and_then(|g| g.get(control)).map(String::as_str))
    }

    /// `MSG_<id>` formatted with printf-style arguments.
    pub fn fmt(&self, id: u16, args: &[Arg<'_>]) -> String {
        sprintf(&self.msg(id), args)
    }
}
```

- [ ] **Step 7: Run the tests**

Run: `cargo test -p rufus-l10n && cargo run -q -p xtask -- nonsense; echo "exit $?"`
Expected: all l10n tests pass; the xtask prints its usage and exits 1.

- [ ] **Step 8: Commit**

```bash
git add Cargo.toml .cargo xtask data crates/rufus-l10n
git commit -m "feat(l10n): rufus.loc parser, printf subset, SizeToHumanReadable; xtask data-sync"
```

---

### Task 13: `rufus-core` — volume label rules (`ToValidLabel` port)

**Files:**
- Create: `crates/rufus-core/Cargo.toml`, `crates/rufus-core/src/lib.rs`, `crates/rufus-core/src/label.rs`
- Modify: `Cargo.toml` (members, workspace deps)
- Test: unit tests in `label.rs`

**Interfaces:**
- Consumes: `rufus_l10n::{Catalog, embedded, size_to_human_readable}` (Task 12).
- Produces: `pub fn rufus_core::label::to_valid_label(label: &str, fat: bool, disk_size: u64, english: &Catalog<'_>) -> String`

- [ ] **Step 1: Create the crate**

Root `Cargo.toml`: add `"crates/rufus-core"` to `members` and `rufus-core = { path = "crates/rufus-core" }` to `[workspace.dependencies]`.

`crates/rufus-core/Cargo.toml`:
```toml
[package]
name = "rufus-core"
description = "Rufus logic shared by every rufus-rs front end"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true

[dependencies]
rufus-l10n.workspace = true

[lints]
workspace = true
```

`crates/rufus-core/src/lib.rs`:
```rust
//! Rufus logic shared by every rufus-rs front end. M1b adds the option
//! rules, the job pipeline and events.

pub mod label;
```

- [ ] **Step 2: Write the failing tests**

`crates/rufus-core/src/label.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use rufus_l10n::embedded;

    fn fat(label: &str, size: u64) -> String {
        to_valid_label(label, true, size, &embedded().catalog("en-US").unwrap())
    }

    fn ntfs(label: &str) -> String {
        to_valid_label(label, false, 8 << 30, &embedded().catalog("en-US").unwrap())
    }

    #[test]
    fn fat_labels_are_uppercased_and_truncated() {
        assert_eq!(fat("My Label", 8 << 30), "MY LABEL");
        assert_eq!(fat("ubuntu 24.04.1 amd64", 8 << 30), "UBUNTU 24_0");
        assert_eq!(fat("a*b?c", 8 << 30), "ABC");
        assert_eq!(fat("Übung", 8 << 30), "_BUNG");
    }

    #[test]
    fn fat_label_cjk_falls_back_to_size() {
        assert_eq!(fat("日本語", 8 << 30), "8 GB");
    }

    #[test]
    fn fat_label_emoji_falls_back_to_size() {
        assert_eq!(fat("🙂", 8_480_000_000), "7_9 GB");
    }

    #[test]
    fn ntfs_labels_keep_case_and_unicode() {
        assert_eq!(ntfs("Ubuntu 24.04"), "Ubuntu 24_04");
        assert_eq!(ntfs("Übung"), "Übung");
        assert_eq!(ntfs(&"x".repeat(40)), "x".repeat(32));
        assert_eq!(ntfs("a*b"), "a*b");
    }
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test -p rufus-core`
Expected: compile error (`to_valid_label` undefined).

- [ ] **Step 4: Implement**

Above the tests in `label.rs`:
```rust
use rufus_l10n::{Catalog, size_to_human_readable};

const FAT_UNAUTHORIZED: &[u8] = b"*?,;:/\\|+=<>[]\"";
const TO_UNDERSCORE: &[u8] = b"\t.";

/// Turns a user or ISO label into one the target file system accepts.
/// Works on UTF-16 code units like upstream (so an emoji counts as two
/// characters). A FAT label made mostly of underscores is replaced by the
/// English disk size, e.g. "7_9 GB".
/// upstream: format.c ToValidLabel @942ed3a4
pub fn to_valid_label(label: &str, fat: bool, disk_size: u64, english: &Catalog<'_>) -> String {
    let underscore = u16::from(b'_');
    let mut units: Vec<u16> = Vec::with_capacity(label.len());
    for u in label.encode_utf16() {
        let ascii = u8::try_from(u).ok().filter(u8::is_ascii);
        if fat {
            if ascii.is_some_and(|b| FAT_UNAUTHORIZED.contains(&b)) {
                continue;
            }
            // A FAT label with extended characters would be rejected.
            if ascii.is_none() {
                units.push(underscore);
                continue;
            }
        }
        if ascii.is_some_and(|b| TO_UNDERSCORE.contains(&b)) {
            units.push(underscore);
            continue;
        }
        units.push(match ascii {
            Some(b) if fat => u16::from(b.to_ascii_uppercase()),
            _ => u,
        });
    }
    if fat {
        units.truncate(11);
        let underscores = units.iter().filter(|&&u| u == underscore).count();
        if units.len() < 2 * underscores {
            return size_to_human_readable(disk_size, english, false, false).replace('.', "_");
        }
    } else {
        units.truncate(32);
    }
    String::from_utf16_lossy(&units)
}
```

- [ ] **Step 5: Run the tests**

Run: `cargo test -p rufus-core`
Expected: 4 tests pass.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml crates/rufus-core
git commit -m "feat(core): port upstream ToValidLabel"
```

---

### Task 14: `rufus-cli` — `scan`, `hash`, `format-image`

**Files:**
- Create: `apps/rufus-cli/Cargo.toml`, `apps/rufus-cli/src/main.rs`
- Modify: `Cargo.toml` (members, workspace deps)
- Test: `apps/rufus-cli/tests/cli.rs`, `apps/rufus-cli/tests/cli_linux.rs`

**Interfaces:**
- Consumes: `FileDevice`, `OffsetDevice`, `BlockDevice` (Task 1); `plan_layout`, `apply_layout`, `DiskIds`, `LayoutRequest`, `Geometry`, `PartitionStyle`, `MainFs`, `ExtraPartitions`, `Mbr` (Tasks 2–4); `FatOptions`, `LocalTime`, `format_fat32`, `format_fat16`, `FatSummary` (Tasks 5–6); `IsoReader`, `IsoOptions`, `Entry` (Tasks 7–10); `hash_reader` (Task 11); `embedded`, `size_to_human_readable` (Task 12); `to_valid_label` (Task 13).
- Produces: the binary `rufus-cli`:
  - `rufus-cli scan <iso> [--no-joliet] [--no-rock-ridge]`
  - `rufus-cli hash <file>`
  - `rufus-cli format-image <image> --size <N[K|M|G|T]> [--sector-size 512] [--scheme mbr|gpt] [--fs fat32|fat16] [--label L] [--cluster BYTES]`

- [ ] **Step 1: Create the crate**

Root `Cargo.toml`: add `"apps/rufus-cli"` to `members`; add `clap = { version = "4.6", features = ["derive"] }` to `[workspace.dependencies]`.

`apps/rufus-cli/Cargo.toml`:
```toml
[package]
name = "rufus-cli"
description = "rufus-rs developer and test harness"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true
publish = false

[dependencies]
clap.workspace = true
rufus-blockdev.workspace = true
rufus-part.workspace = true
rufus-fat.workspace = true
rufus-iso.workspace = true
rufus-hash.workspace = true
rufus-l10n.workspace = true
rufus-core.workspace = true

[dev-dependencies]
tempfile.workspace = true
serde_json.workspace = true

[lints]
workspace = true
```

- [ ] **Step 2: Write the failing tests**

`apps/rufus-cli/tests/cli.rs`:
```rust
use rufus_blockdev::{BlockDevice, FileDevice};
use rufus_part::Mbr;
use std::path::PathBuf;
use std::process::Command;

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rufus-cli"))
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../crates/rufus-iso/tests/fixtures").join(name)
}

#[test]
fn scan_lists_an_iso() {
    let out = cli().arg("scan").arg(fixture("eltorito.iso")).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("Image is an ISO9660 image"));
    assert!(text.contains("Volume label: BOOT_VOL"));
    assert!(text.contains("El Torito: 2 boot entries"));
    assert!(text.contains("/boot/grub/grub.cfg (14 bytes)"), "{text}");
}

#[test]
fn hash_prints_upstream_format() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("abc.txt");
    std::fs::write(&f, b"abc").unwrap();
    let out = cli().arg("hash").arg(&f).output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("  MD5:    900150983cd24fb0d6963f7d28e17f72"));
    assert!(text.contains("  SHA1:   a9993e364706816aba3e25717850c26c9cd0d89d"));
}

#[test]
fn format_image_creates_mbr_fat32() {
    let dir = tempfile::tempdir().unwrap();
    let img = dir.path().join("disk.img");
    let out = cli()
        .args(["format-image", "--size", "512M", "--label", "my stick"])
        .arg(&img)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("● Creating Main Data Partition (offset: 1048576"), "{text}");

    let mut dev = FileDevice::open(&img, false, 512).unwrap();
    let mbr = Mbr::read(&mut dev).unwrap();
    let p = mbr.partitions[0].unwrap();
    assert_eq!((p.start_lba, p.part_type), (2048, 0x0c));
    let mut boot = [0u8; 512];
    dev.read_at(u64::from(p.start_lba) * 512, &mut boot).unwrap();
    assert_eq!(&boot[71..82], b"MY STICK   ");
    assert_eq!(&boot[82..90], b"FAT32   ");
}

#[test]
fn bad_arguments_fail_cleanly() {
    let out = cli().args(["format-image", "--size", "12Q", "x.img"]).output().unwrap();
    assert!(!out.status.success());
    let out = cli().arg("scan").arg("/definitely/not/here.iso").output().unwrap();
    assert!(!out.status.success());
}
```

`apps/rufus-cli/tests/cli_linux.rs`:
```rust
#![cfg(target_os = "linux")]

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::process::Command;

#[test]
fn formatted_gpt_image_passes_fsck() {
    let dir = tempfile::tempdir().unwrap();
    let img = dir.path().join("disk.img");
    let out = Command::new(env!("CARGO_BIN_EXE_rufus-cli"))
        .args(["format-image", "--size", "512M", "--scheme", "gpt", "--label", "RUFUS"])
        .arg(&img)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

    let out = Command::new("sfdisk").arg("-J").arg(&img).output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let p = &v["partitiontable"]["partitions"][0];
    let start = p["start"].as_u64().unwrap() * 512;
    let size = p["size"].as_u64().unwrap() * 512;

    let part = dir.path().join("part.img");
    let mut src = File::open(&img).unwrap();
    src.seek(SeekFrom::Start(start)).unwrap();
    std::io::copy(&mut src.take(size), &mut File::create(&part).unwrap()).unwrap();
    let fsck = Command::new("fsck.fat").arg("-n").arg(&part).output().unwrap();
    assert!(fsck.status.success(), "{}", String::from_utf8_lossy(&fsck.stdout));
    let label = Command::new("fatlabel").arg(&part).output().unwrap();
    assert_eq!(String::from_utf8_lossy(&label.stdout).trim(), "RUFUS");
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test -p rufus-cli`
Expected: FAIL. `main.rs` doesn't exist yet, so the binary won't build.

- [ ] **Step 4: Implement the CLI**

`apps/rufus-cli/src/main.rs`:
```rust
//! rufus-rs developer and test harness. Not a user-facing product.

use clap::{Parser, Subcommand, ValueEnum};
use rufus_blockdev::{BlockDevice, FileDevice, OffsetDevice};
use rufus_core::label::to_valid_label;
use rufus_fat::{FatOptions, FatSummary, LocalTime, format_fat16, format_fat32};
use rufus_iso::{IsoOptions, IsoReader};
use rufus_l10n::{embedded, size_to_human_readable};
use rufus_part::{DiskIds, ExtraPartitions, Geometry, LayoutRequest, MainFs, PartitionStyle, apply_layout, plan_layout};
use std::collections::HashSet;
use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::time::{SystemTime, UNIX_EPOCH};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Parser)]
#[command(name = "rufus-cli", version, about = "rufus-rs developer and test harness")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// List the contents of an ISO image
    Scan {
        iso: PathBuf,
        #[arg(long)]
        no_joliet: bool,
        #[arg(long)]
        no_rock_ridge: bool,
    },
    /// Compute MD5, SHA-1, SHA-256 and SHA-512 of a file
    Hash { file: PathBuf },
    /// Create a partitioned, formatted disk image
    FormatImage(FormatArgs),
}

#[derive(clap::Args)]
struct FormatArgs {
    image: PathBuf,
    /// Image size, e.g. 512M or 8G
    #[arg(long)]
    size: String,
    #[arg(long, default_value_t = 512)]
    sector_size: u32,
    #[arg(long, value_enum, default_value_t = Scheme::Mbr)]
    scheme: Scheme,
    #[arg(long, value_enum, default_value_t = Fs::Fat32)]
    fs: Fs,
    #[arg(long, default_value = "")]
    label: String,
    /// Cluster size in bytes (0 = default)
    #[arg(long, default_value_t = 0)]
    cluster: u32,
}

#[derive(Clone, Copy, ValueEnum)]
enum Scheme {
    Mbr,
    Gpt,
}

#[derive(Clone, Copy, ValueEnum)]
enum Fs {
    Fat16,
    Fat32,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.cmd {
        Cmd::Scan { iso, no_joliet, no_rock_ridge } => scan(&iso, !no_joliet, !no_rock_ridge),
        Cmd::Hash { file } => hash(&file),
        Cmd::FormatImage(args) => format_image(&args),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn scan(path: &Path, joliet: bool, rock_ridge: bool) -> Result<()> {
    let mut iso = IsoReader::open(BufReader::new(File::open(path)?), IsoOptions { joliet, rock_ridge })?;
    println!("Image is an ISO9660 image");
    println!("Volume label: {}", iso.volume_id());
    println!("Joliet level: {}", iso.joliet_level());
    println!("Rock Ridge: {}", if iso.has_rock_ridge() { "yes" } else { "no" });
    match iso.boot_catalog()? {
        Some(cat) => {
            println!("El Torito: {} boot entries", cat.entries.len());
            for (i, e) in cat.entries.iter().enumerate() {
                println!(
                    "  [{i}] platform 0x{:02X}, {}, media 0x{:02X}, sectors {}, lba {}",
                    e.platform,
                    if e.bootable { "bootable" } else { "not bootable" },
                    e.media_type,
                    e.sector_count,
                    e.load_rba
                );
            }
        }
        None => println!("El Torito: none"),
    }
    let mut lines = Vec::new();
    let (mut files, mut dirs, mut bytes) = (0u64, 0u64, 0u64);
    let mut seen = HashSet::new();
    let mut stack = vec![(String::new(), iso.root())];
    while let Some((prefix, dir)) = stack.pop() {
        if !seen.insert(dir.extents.first().map(|e| e.lba)) {
            continue; // Rock Ridge relocation loops
        }
        for e in iso.read_dir(&dir)? {
            let path = format!("{prefix}/{}", e.name);
            if e.is_dir {
                dirs += 1;
                lines.push(format!("{path}/"));
                stack.push((path, e));
            } else if let Some(target) = &e.symlink {
                files += 1;
                lines.push(format!("{path} -> {target}"));
            } else {
                files += 1;
                bytes += e.size;
                lines.push(format!("{path} ({} bytes)", e.size));
            }
        }
    }
    lines.sort();
    for l in lines {
        println!("  {l}");
    }
    println!("Files: {files}, directories: {dirs}, total size: {bytes} bytes");
    Ok(())
}

fn hash(path: &Path) -> Result<()> {
    let hashes = rufus_hash::hash_reader(BufReader::new(File::open(path)?), &AtomicBool::new(false), |_| {})?;
    for line in hashes.log_lines() {
        println!("{line}");
    }
    Ok(())
}

fn parse_size(s: &str) -> Result<u64> {
    let (digits, multiplier) = match s.chars().last() {
        Some('K' | 'k') => (&s[..s.len() - 1], 1u64 << 10),
        Some('M' | 'm') => (&s[..s.len() - 1], 1 << 20),
        Some('G' | 'g') => (&s[..s.len() - 1], 1 << 30),
        Some('T' | 't') => (&s[..s.len() - 1], 1 << 40),
        _ => (s, 1),
    };
    digits
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(multiplier))
        .ok_or_else(|| format!("invalid size '{s}'").into())
}

fn now() -> LocalTime {
    let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    LocalTime::from_unix(d.as_secs() as i64, d.subsec_millis() as u16)
}

fn print_summary(s: &FatSummary) {
    let cluster = s.sectors_per_cluster * s.bytes_per_sector;
    println!("Cluster size {cluster} bytes, {} bytes per sector", s.bytes_per_sector);
    println!("{} Reserved sectors, {} sectors per FAT, {} FATs", s.reserved_sectors, s.fat_sectors, s.num_fats);
    println!("{} Total clusters", s.cluster_count);
}

fn format_image(a: &FormatArgs) -> Result<()> {
    let size = parse_size(&a.size)?;
    let english = embedded().catalog("en-US").ok_or("en-US translation missing")?;
    let main_fs = match a.fs {
        Fs::Fat16 => MainFs::Fat16,
        Fs::Fat32 => MainFs::Fat32,
    };
    let style = match a.scheme {
        Scheme::Mbr => PartitionStyle::Mbr,
        Scheme::Gpt => PartitionStyle::Gpt,
    };
    let layout = plan_layout(&LayoutRequest {
        geometry: Geometry::new(size, a.sector_size),
        style,
        main_fs,
        cluster_size: u64::from(a.cluster),
        extra: ExtraPartitions::default(),
        old_bios_fixes: false,
        write_as_esp: false,
        bootable: false,
        persistence_size: 0,
        uefi_ntfs_size: 0,
    })?;

    let mut dev = FileDevice::create(&a.image, size, a.sector_size)?;
    apply_layout(&mut dev, &layout, &DiskIds::random(layout.partitions.len(), false))?;
    for p in &layout.partitions {
        let suffix = if p.name.contains("Partition") { "" } else { " Partition" };
        println!(
            "● Creating {}{suffix} (offset: {}, size: {})",
            p.name,
            p.offset,
            size_to_human_readable(p.size, &english, false, false)
        );
    }

    let main = layout.main();
    let mut opts = FatOptions::new(&to_valid_label(&a.label, true, size, &english), now());
    opts.cluster_size = a.cluster;
    opts.hidden_sectors = u32::try_from(main.offset / u64::from(a.sector_size))?;
    let summary = {
        let mut part = OffsetDevice::new(&mut dev, main.offset, main.size)?;
        match a.fs {
            Fs::Fat32 => format_fat32(&mut part, &opts)?,
            Fs::Fat16 => format_fat16(&mut part, &opts)?,
        }
    };
    print_summary(&summary);
    dev.flush()?;
    println!("Format completed.");
    Ok(())
}
```

- [ ] **Step 5: Run the tests**

Run: `cargo test -p rufus-cli`
Expected: the 4 tests in `cli.rs` and `formatted_gpt_image_passes_fsck` pass.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml apps/rufus-cli
git commit -m "feat(cli): scan, hash and format-image developer commands"
```

---

### Task 15: Fuzzing

**Files:**
- Create: `fuzz/Cargo.toml`, `fuzz/fuzz_targets/iso_walk.rs`, `fuzz/fuzz_targets/boot_catalog.rs`, `fuzz/fuzz_targets/partition_tables.rs`
- Create: `.github/workflows/fuzz.yml`
- Test: the fuzz targets themselves (a short local run)

**Interfaces:**
- Consumes: `IsoReader`, `IsoOptions`, `parse_boot_catalog` (Tasks 7–10); `Mbr`, `Gpt` (Tasks 2–3); `MemDevice` (Task 1).
- Produces: three `cargo fuzz` targets and a nightly CI job.

- [ ] **Step 1: Create the fuzz crate**

Install once: `rustup toolchain install nightly && cargo install cargo-fuzz`.

`fuzz/Cargo.toml`:
```toml
[package]
name = "rufus-fuzz"
version = "0.0.0"
edition = "2024"
publish = false

[package.metadata]
cargo-fuzz = true

[dependencies]
libfuzzer-sys = "0.4"
rufus-blockdev = { path = "../crates/rufus-blockdev" }
rufus-iso = { path = "../crates/rufus-iso" }
rufus-part = { path = "../crates/rufus-part" }

[workspace]

[[bin]]
name = "iso_walk"
path = "fuzz_targets/iso_walk.rs"
test = false
doc = false
bench = false

[[bin]]
name = "boot_catalog"
path = "fuzz_targets/boot_catalog.rs"
test = false
doc = false
bench = false

[[bin]]
name = "partition_tables"
path = "fuzz_targets/partition_tables.rs"
test = false
doc = false
bench = false
```

`fuzz/fuzz_targets/iso_walk.rs`:
```rust
#![no_main]

use libfuzzer_sys::fuzz_target;
use rufus_iso::{IsoOptions, IsoReader};
use std::io::{Cursor, sink};

fuzz_target!(|data: &[u8]| {
    for opts in [IsoOptions::default(), IsoOptions { joliet: false, rock_ridge: true }] {
        let Ok(mut iso) = IsoReader::open(Cursor::new(data), opts) else { continue };
        let _ = iso.boot_catalog();
        let mut stack = vec![iso.root()];
        let mut budget = 10_000;
        while let Some(dir) = stack.pop() {
            if budget == 0 {
                break;
            }
            budget -= 1;
            let Ok(entries) = iso.read_dir(&dir) else { continue };
            for e in entries {
                if e.is_dir {
                    stack.push(e);
                } else {
                    let _ = iso.read_file(&e, &mut sink());
                }
            }
        }
    }
});
```

`fuzz/fuzz_targets/boot_catalog.rs`:
```rust
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = rufus_iso::parse_boot_catalog(data);
});
```

`fuzz/fuzz_targets/partition_tables.rs`:
```rust
#![no_main]

use libfuzzer_sys::fuzz_target;
use rufus_blockdev::MemDevice;
use rufus_part::{Gpt, Mbr};

fuzz_target!(|data: &[u8]| {
    let _ = Mbr::parse(data);
    let mut bytes = data.to_vec();
    bytes.resize(bytes.len().max(64 * 512), 0);
    let _ = Gpt::read(&mut MemDevice::new(0, 512));
    let _ = Gpt::read(&mut MemDevice::from_vec(bytes, 512));
});
```

- [ ] **Step 2: Seed the corpus and run each target briefly**

```bash
mkdir -p fuzz/corpus/iso_walk
cp crates/rufus-iso/tests/fixtures/*.iso fuzz/corpus/iso_walk/
cd fuzz
cargo +nightly fuzz run iso_walk -- -max_total_time=60
cargo +nightly fuzz run boot_catalog -- -max_total_time=30
cargo +nightly fuzz run partition_tables -- -max_total_time=30
cd ..
```
Expected: each run ends with `Done ... runs` and no crash. If a crash is found, add its input as a regression test in the owning crate (for example a `#[test]` that feeds the artifact bytes to `IsoReader::open` and walks it), fix the code, and rerun.

- [ ] **Step 3: Add the nightly workflow**

`.github/workflows/fuzz.yml`:
```yaml
name: Fuzz
on:
  schedule:
    - cron: "17 3 * * *"
  workflow_dispatch:

jobs:
  fuzz:
    runs-on: ubuntu-24.04
    strategy:
      fail-fast: false
      matrix:
        target: [iso_walk, boot_catalog, partition_tables]
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly
      - run: cargo install cargo-fuzz --locked
      - name: Seed corpus
        run: |
          mkdir -p fuzz/corpus/iso_walk
          cp crates/rufus-iso/tests/fixtures/*.iso fuzz/corpus/iso_walk/
      - name: Fuzz ${{ matrix.target }}
        working-directory: fuzz
        run: cargo +nightly fuzz run ${{ matrix.target }} -- -max_total_time=900
      - uses: actions/upload-artifact@v4
        if: failure()
        with:
          name: fuzz-artifacts-${{ matrix.target }}
          path: fuzz/artifacts
```

- [ ] **Step 4: Commit**

```bash
git add fuzz/Cargo.toml fuzz/fuzz_targets .github/workflows/fuzz.yml
git commit -m "test: cargo-fuzz targets for ISO, El Torito and partition parsers"
```

---

### Task 16: Parity inventory and upstream tracking

**Files:**
- Create: `docs/parity.md`, `docs/upstream-tracking.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: everything above.
- Produces: the documents spec §7 requires. M1b and later plans append rows.

- [ ] **Step 1: Write `docs/parity.md`**

```markdown
# Parity inventory

One row per upstream Rufus behaviour, taken from the upstream source at the
baseline in `data/UPSTREAM`. Status: ✅ done · 🟡 open divergence to verify ·
⏳ later milestone.

| Area | Upstream (file:function @942ed3a4) | rufus-rs | Test | Status |
|---|---|---|---|---|
| Partition layout (offsets, sizes, extra partitions) | drive.c:CreatePartition | `rufus_part::plan_layout` | `crates/rufus-part/tests/layout.rs` | ✅ (63 sectors/track assumed, as Windows reports for USB) |
| Partition clearing before the table write | drive.c:ClearPartition | `rufus_part::apply_layout` | `apply_mbr_clears_and_writes_table` | ✅ |
| MBR UEFI marker | rufus.h:MBR_UEFI_MARKER | `DiskIds::random(_, true)` | `apply_mbr_clears_and_writes_table` | ✅ |
| GPT types, names, UEFI:NTFS no-drive-letter attribute | drive.c:CreatePartition | `Layout::to_gpt` | `gpt_types_and_attributes` | ✅ |
| Large FAT32 format (> 32 GB or forced) | format_fat32.c:FormatLargeFAT32 | `rufus_fat::format_fat32` | `crates/rufus-fat` tests | ✅ |
| FAT32 < 32 GB | format.c:FormatPartition → fmifs FormatEx (Windows) | `rufus_fat::format_fat32` (same algorithm for every size, spec D3) | — | 🟡 may differ from FormatEx near cluster-count limits (e.g. 256 MiB with 4 KiB clusters is rejected); compare with Windows golden files in M1b |
| FAT16 ("FAT") format | fmifs FormatEx | `rufus_fat::format_fat16` (fatgen103) | `crates/rufus-fat` tests | 🟡 BPB field choices (reserved sectors, root entries) to compare with FormatEx golden files in M1b |
| FAT16 default cluster size | rufus.c:SetClusterSizes | `default_fat16_cluster_size` | `default_cluster_sizes_follow_upstream` | ✅ |
| FAT volume serial | format_fat32.c:GetVolumeID | `rufus_fat::volume_id` | `volume_id_matches_upstream_example` | ✅ (local time comes from the platform in M1b; the CLI uses UTC) |
| FAT volume label | SetVolumeLabel (Windows) | BPB + root-directory label entry | `fat32_passes_fsck_and_mtools_roundtrip` | ✅ |
| Label sanitising | format.c:ToValidLabel | `rufus_core::label::to_valid_label` | `crates/rufus-core` tests | ✅ |
| Size strings | stdio.c:SizeToHumanReadable | `rufus_l10n::size_to_human_readable` | `matches_upstream_formatting` | ✅ |
| Translation file parsing | parser.c:get_loc_data_file, get_loc_cmd | `rufus_l10n::parse` | `crates/rufus-l10n` tests | ✅ (`f` font commands ignored: Win32 only) |
| Hashes (MD5/SHA-1/SHA-256/SHA-512) and log format | hash.c | `rufus-hash` | `crates/rufus-hash` tests | ✅ |
| ISO9660 reading, name translation | libcdio iso9660 (via iso.c) | `rufus-iso` | `crates/rufus-iso/tests` | ✅ |
| Joliet / Rock Ridge selection policy | iso.c:ExtractISO (ISO_EXTENSION_MASK) | `IsoOptions` (policy in rufus-core) | — | ⏳ M1b |
| Rock Ridge symlink handling during extraction | iso.c:iso_extract_files | — | — | ⏳ M1b |
| El Torito catalog | libcdio | `rufus_iso::parse_boot_catalog` | `crates/rufus-iso/tests/eltorito.rs` | ✅ |
| UDF reading | libcdio udf (iso.c:udf_extract_files) | — | — | ⏳ M2 |
| Cluster-size and file-system option rules | rufus.c:SetClusterSizes, SetFileSystemAndClusterSize | — | — | ⏳ M1b |
```

- [ ] **Step 2: Write `docs/upstream-tracking.md`**

```markdown
# Upstream tracking

Baseline: pbatard/rufus `942ed3a4` ("[core] drop the use of Group Policies to
set NoDriveTypeAutorun", 2026-09-21). Every upstream commit after the baseline
gets a row. Review at the end of every milestone and on every upstream release.

Verdicts: **ported** (with the rufus-rs commit) · **n/a** (with a reason) ·
**pending**.

To find the Rust code an upstream change affects, search for its marker:
`git grep "upstream: <file>.c <Function>"`.

| Upstream commit | Subject | Upstream files/functions | Verdict | rufus-rs commit / reason |
|---|---|---|---|---|
```

- [ ] **Step 3: Update `README.md`**

Replace the status block with:
```markdown
> **Status:** M1a (foundations) — partition tables and layout, FAT16/FAT32
> formatters, ISO9660/Joliet/Rock Ridge/El Torito reader, hashing, and
> localisation as libraries, plus a developer CLI (`cargo run -p rufus-cli --
> --help`). No end-user application yet. This is not official Rufus and is not
> endorsed by the Rufus project; the public name will be chosen before the
> first release.

- Design: [`docs/superpowers/specs/2026-09-25-rufus-rs-architecture-design.md`](docs/superpowers/specs/2026-09-25-rufus-rs-architecture-design.md)
- Parity with upstream Rufus: [`docs/parity.md`](docs/parity.md)
```

- [ ] **Step 4: Final verification**

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`
Expected: all clean, all tests pass.

- [ ] **Step 5: Commit and push**

```bash
git add docs/parity.md docs/upstream-tracking.md README.md
git commit -m "docs: parity inventory and upstream tracking for M1a"
git push
gh run watch --exit-status
```
Expected: CI green on Linux and Windows.
