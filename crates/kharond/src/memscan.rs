//! Canary scan of this process's own memory (REQ-MEM-003,
//! REQ-CRY-006): count occurrences of a needle in this process's
//! readable mappings.
//!
//! The mappings come from `/proc/self/maps`, but the bytes are read
//! with `process_vm_readv(2)` on *self*, not through
//! `/proc/self/mem`: `harden_process()` sets `PR_SET_DUMPABLE 0`
//! (REQ-MEM-001), after which the kernel re-owns `/proc/self/*` to
//! root and opening `/proc/self/mem` fails with `EACCES` for the
//! daemon's own non-root uid. Same-thread-group
//! `process_vm_readv` skips the ptrace access check, so the scan
//! works under hardening — and a bad page just returns `EFAULT`,
//! never a signal. (Found in PR #81 review: the `/proc/self/mem`
//! version silently scanned nothing in a real hardened daemon.)
//!
//! A scan that cannot read is an **error**, never 0 hits: a failed
//! scanner must not be able to produce a passing zero-hit AC. The
//! caller (the owner socket's feature-gated `scan` op) answers
//! `scan_unavailable` on error.
//!
//! REQ-MEM-003's acceptance test is a scan of the running daemon:
//! after unlock, the master/export password must occur 0 times;
//! after lock, the session's secret material must occur 0 times.
//! The scan runs in-process (a hardened kharond is non-dumpable, so
//! no other process may read its memory — REQ-MEM-001), which
//! creates self-reference problems this module is careful about:
//!
//! - The needle itself is in memory (the caller holds it). The
//!   caller passes its byte range as an exclusion; matches starting
//!   inside an excluded range are not counted.
//! - The scan's own buffers must not manufacture phantom hits: a
//!   buffer that holds a *copy* of scanned memory would itself be
//!   scanned later and re-count the needle at the buffer's own
//!   addresses. So chunks are counted in place in the single read
//!   buffer (whose range is excluded), and the only other copy —
//!   the few bytes of tail kept for chunk-straddling matches —
//!   lives in one small stable allocation whose range is likewise
//!   excluded for the whole scan.
//! - Not every mapped page is readable (guard pages, regions
//!   being torn down). Unreadable pages are skipped, never fatal:
//!   a skipped page can hide a hit, so this is best available
//!   evidence — the regions that matter (heap, stacks) are
//!   readable. But if *nothing at all* could be read, the scan is
//!   an error (see above), not a zero.
//!
//! Linux only; on other platforms the scan is unavailable (an
//! error, likewise never a silent 0).

use std::ops::Range;

/// Why a scan could not be performed. A scan error must surface to
/// the caller as `scan_unavailable`; it is never a hit count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanError {
    /// The needle was empty or over the size cap.
    BadNeedle,
    /// `/proc/self/maps` could not be read or listed no regions.
    NoRegions,
    /// Regions were listed but not one byte could be read.
    NothingScanned,
    /// The platform has no self-scan (non-Linux).
    Unavailable,
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::BadNeedle => "bad needle",
            Self::NoRegions => "no readable regions listed",
            Self::NothingScanned => "no mapped byte could be read",
            Self::Unavailable => "canary scan unavailable on this platform",
        })
    }
}

impl std::error::Error for ScanError {}

/// One readable mapping from `/proc/self/maps`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Region {
    /// Virtual address range.
    pub range: Range<usize>,
}

#[cfg(target_os = "linux")]
fn readable_regions() -> Result<Vec<Region>, ScanError> {
    let maps = std::fs::read_to_string("/proc/self/maps").map_err(|_| ScanError::NoRegions)?;
    let mut out = Vec::new();
    for line in maps.lines() {
        // "7f…-7f… r--p 00000000 00:00 0  /path" — fields: range,
        // perms, offset, dev, inode, optional pathname.
        let mut parts = line.split_whitespace();
        let (Some(range), Some(perms)) = (parts.next(), parts.next()) else {
            continue;
        };
        if !perms.starts_with('r') {
            continue;
        }
        let Some((lo, hi)) = range.split_once('-') else {
            continue;
        };
        let (Ok(lo), Ok(hi)) = (usize::from_str_radix(lo, 16), usize::from_str_radix(hi, 16))
        else {
            continue;
        };
        if hi > lo {
            out.push(Region { range: lo..hi });
        }
    }
    if out.is_empty() {
        return Err(ScanError::NoRegions);
    }
    Ok(out)
}

/// Count occurrences of `needle` in this process's readable memory,
/// ignoring any match that starts inside one of `exclude` (virtual
/// address ranges, e.g. the needle's own buffer). Overlapping
/// occurrences each count. An empty needle is an error.
///
/// # Errors
/// [`ScanError`] when the scan could not actually read: no regions
/// listed, or not one byte read. Individual unreadable pages inside
/// a region are skipped (see the module docs), not errors.
#[cfg(target_os = "linux")]
pub fn count_occurrences(needle: &[u8], exclude: &[Range<usize>]) -> Result<usize, ScanError> {
    use std::io::IoSliceMut;

    use nix::sys::uio::{RemoteIoVec, process_vm_readv};
    use nix::unistd::Pid;

    if needle.is_empty() || needle.len() > 4096 {
        return Err(ScanError::BadNeedle);
    }
    let regions = readable_regions()?;
    let pid = Pid::this();
    // The single read buffer (64 KiB). Its range is excluded: it
    // transiently holds copies of everything scanned.
    let mut buf = vec![0u8; 64 * 1024];
    let buf_range = range_of(&buf);
    // Tail of the previous chunk (at most needle-1 bytes), for
    // matches straddling a chunk boundary. One stable allocation,
    // excluded for the whole scan like the read buffer.
    let mut tail: Vec<u8> = Vec::with_capacity(needle.len());
    // The tail's whole allocation (len ≤ capacity), not just the
    // live slice: freed-former-contents live in the capacity too.
    let tail_range = {
        let p = tail.as_ptr() as usize;
        p..p + tail.capacity()
    };
    let excluded =
        |at: usize, extra: &[Range<usize>]| exclude.iter().chain(extra).any(|r| r.contains(&at));

    let mut hits = 0usize;
    let mut bytes_scanned = 0usize;
    for region in regions {
        tail.clear();
        let mut tail_addr = region.range.start;
        let mut addr = region.range.start;
        while addr < region.range.end {
            let want = (region.range.end - addr).min(buf.len());
            // One chunk via process_vm_readv on self. A short read
            // means the transfer stopped at an unreadable page:
            // the bytes up to it are real, the page is skipped.
            let read = {
                let mut local = [IoSliceMut::new(&mut buf[..want])];
                let remote = [RemoteIoVec {
                    base: addr,
                    len: want,
                }];
                process_vm_readv(pid, &mut local, &remote)
            };
            match read {
                Ok(n) if n > 0 => {
                    bytes_scanned += n;
                    let chunk = &buf[..n];
                    // Matches fully inside this chunk, at their
                    // true addresses.
                    hits += count_in(
                        chunk,
                        addr,
                        needle,
                        exclude,
                        &[buf_range.clone(), tail_range.clone()],
                    );
                    // Matches starting in the tail and straddling
                    // into this chunk (their start was not counted
                    // with the previous chunk, which ended before
                    // the match completed).
                    if !tail.is_empty() {
                        for off in 0..tail.len() {
                            let at = tail_addr + off;
                            let in_tail = &tail[off..];
                            let from_chunk = needle.len() - in_tail.len();
                            if from_chunk == 0
                                || from_chunk > chunk.len()
                                || excluded(at, &[buf_range.clone(), tail_range.clone()])
                            {
                                continue;
                            }
                            if in_tail == &needle[..in_tail.len()]
                                && chunk[..from_chunk] == needle[in_tail.len()..]
                            {
                                hits += 1;
                            }
                        }
                    }
                    // Keep the last needle-1 bytes as the next tail.
                    let keep = needle.len().saturating_sub(1).min(n);
                    tail.clear();
                    tail.extend_from_slice(&chunk[n - keep..]);
                    tail_addr = addr + n - keep;
                    addr += n;
                    if n < want {
                        // Stopped at an unreadable page: skip it
                        // and break contiguity (drop the tail).
                        tail.clear();
                        addr += 4096 - (addr % 4096);
                    }
                }
                _ => {
                    // Unreadable page(s): skip one page and break
                    // contiguity (drop the tail).
                    tail.clear();
                    addr += 4096 - (addr % 4096);
                }
            }
        }
    }
    if bytes_scanned == 0 {
        return Err(ScanError::NothingScanned);
    }
    Ok(hits)
}

fn range_of(buf: &[u8]) -> Range<usize> {
    let ptr = buf.as_ptr_range();
    (ptr.start as usize)..(ptr.end as usize)
}

/// Count occurrences of `needle` in `window` (whose first byte is
/// at virtual address `window_addr`), skipping matches that start
/// inside an excluded range.
fn count_in(
    window: &[u8],
    window_addr: usize,
    needle: &[u8],
    exclude: &[Range<usize>],
    extra_exclude: &[Range<usize>],
) -> usize {
    if needle.len() > window.len() {
        return 0;
    }
    let mut hits = 0;
    let mut i = 0;
    while i + needle.len() <= window.len() {
        if window[i] == needle[0] && &window[i..i + needle.len()] == needle {
            let at = window_addr + i;
            if !exclude.iter().chain(extra_exclude).any(|r| r.contains(&at)) {
                hits += 1;
            }
            i += 1;
        } else {
            i += 1;
        }
    }
    hits
}

/// Count occurrences of `needle` in this process's readable memory
/// (non-Linux: no self-scan exists, so the scan is *unavailable* —
/// an error, never a silent 0 that could pass a zero-hit AC).
#[cfg(not(target_os = "linux"))]
pub fn count_occurrences(_needle: &[u8], _exclude: &[Range<usize>]) -> Result<usize, ScanError> {
    Err(ScanError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_a_planted_canary_and_respects_exclusions() {
        // Built at runtime so the literal is not sitting in .rodata
        // (which is itself a readable mapping and would be counted).
        let canary = format!("MEMSCAN-CANARY-{}-{}", "planted", "9e27");
        let leaked: &'static [u8] = Box::leak(canary.clone().into_bytes().into_boxed_slice());
        let hits = count_occurrences(leaked, &[]).expect("scan must be able to read self");
        assert!(hits >= 1, "planted canary must be found");
        // Excluding the leaked buffer's own range must remove at
        // least that copy (the `canary` String and its clones in
        // this test are other copies, so only check it drops).
        let range = (leaked.as_ptr() as usize)..(leaked.as_ptr() as usize + leaked.len());
        let excluded =
            count_occurrences(leaked, std::slice::from_ref(&range)).expect("scan must read");
        assert!(excluded < hits, "exclusion must hide the named copy");
    }

    #[test]
    fn empty_needle_is_an_error_not_a_zero() {
        // A failed scan must never masquerade as a passing
        // zero-hit result (PR #81 review, item 2).
        assert_eq!(count_occurrences(&[], &[]), Err(ScanError::BadNeedle));
    }

    #[test]
    fn absent_needle_counts_zero() {
        // Callers always exclude the needle's own buffer (it is,
        // necessarily, in memory); with that exclusion a needle
        // that was never planted anywhere else counts 0. The
        // needle is built through `black_box` so the compiler
        // cannot const-fold this literal-only `format!` into a
        // static copy in .rodata (which the scan would then
        // legitimately find).
        let frag = std::hint::black_box("planted-41".to_string());
        let needle = format!("MEMSCAN-ABSENT-never-{frag}");
        let range = (needle.as_ptr() as usize)..(needle.as_ptr() as usize + needle.len());
        assert_eq!(count_occurrences(needle.as_bytes(), &[range]), Ok(0));
    }
}
