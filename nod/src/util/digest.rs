use bytes::Bytes;
use digest::Digest;
use tracing::instrument;

use crate::{
    common::HashBytes,
    io::nkit::NKitHeader,
    write::{DiscFinalization, ProcessOptions},
};

/// Hashes a byte slice with SHA-1.
#[instrument(skip_all)]
pub fn sha1_hash(buf: &[u8]) -> HashBytes { HashBytes::from(sha1::Sha1::digest(buf)) }

/// Hashes a byte slice with XXH64.
#[allow(unused_braces)] // https://github.com/rust-lang/rust/issues/116347
#[instrument(skip_all)]
pub fn xxh64_hash(buf: &[u8]) -> u64 { xxhash_rust::xxh64::xxh64(buf, 0) }

#[cfg(all(feature = "threading", not(target_family = "wasm")))]
mod multi_threaded {
    use std::{thread, thread::JoinHandle};

    use crossbeam_channel::Sender;

    use super::*;

    type DigestThread = (Sender<Bytes>, JoinHandle<DigestResult>);

    fn digest_thread<H>() -> DigestThread
    where H: Hasher + Send + 'static {
        let (tx, rx) = crossbeam_channel::bounded::<Bytes>(1);
        let handle = thread::Builder::new()
            .name(format!("Digest {}", H::NAME))
            .spawn(move || {
                let mut hasher = H::new();
                while let Ok(data) = rx.recv() {
                    hasher.update(data.as_ref());
                }
                hasher.finalize()
            })
            .expect("Failed to spawn digest thread");
        (tx, handle)
    }

    pub struct DigestManager {
        threads: Vec<DigestThread>,
    }

    impl DigestManager {
        pub fn new(options: &ProcessOptions) -> Self {
            let mut threads = Vec::new();
            if options.digest_crc32 {
                threads.push(digest_thread::<crc32fast::Hasher>());
            }
            if options.digest_md5 {
                threads.push(digest_thread::<md5::Md5>());
            }
            if options.digest_sha1 {
                threads.push(digest_thread::<sha1::Sha1>());
            }
            if options.digest_xxh64 {
                threads.push(digest_thread::<xxhash_rust::xxh64::Xxh64>());
            }
            DigestManager { threads }
        }

        #[instrument(name = "DigestManager::send", skip_all)]
        pub fn send(&self, data: Bytes) {
            let mut sent = 0usize;
            // Non-blocking send to all threads
            for (idx, (tx, _)) in self.threads.iter().enumerate() {
                if tx.try_send(data.clone()).is_ok() {
                    sent |= 1 << idx;
                }
            }
            // Blocking send to any remaining threads
            for (idx, (tx, _)) in self.threads.iter().enumerate() {
                if sent & (1 << idx) == 0 {
                    tx.send(data.clone()).expect("Failed to send data to digest thread");
                }
            }
        }

        #[instrument(name = "DigestManager::finish", skip_all)]
        pub fn finish(self) -> DigestResults {
            let mut results = DigestResults { crc32: None, md5: None, sha1: None, xxh64: None };
            for (tx, handle) in self.threads {
                drop(tx); // Close channel
                match handle.join().unwrap() {
                    DigestResult::Crc32(v) => results.crc32 = Some(v),
                    DigestResult::Md5(v) => results.md5 = Some(v),
                    DigestResult::Sha1(v) => results.sha1 = Some(v),
                    DigestResult::Xxh64(v) => results.xxh64 = Some(v),
                }
            }
            results
        }
    }
}

#[cfg(not(all(feature = "threading", not(target_family = "wasm"))))]
mod single_threaded {
    use std::cell::RefCell;

    use super::*;

    pub struct DigestManager {
        hashers: Vec<RefCell<Box<dyn Hasher>>>,
    }

    impl DigestManager {
        pub fn new(options: &ProcessOptions) -> Self {
            let mut hashers = Vec::<RefCell<Box<dyn Hasher>>>::new();
            if options.digest_crc32 {
                hashers.push(RefCell::new(Box::new(crc32fast::Hasher::new())));
            }
            if options.digest_md5 {
                hashers.push(RefCell::new(Box::new(md5::Md5::new())));
            }
            if options.digest_sha1 {
                hashers.push(RefCell::new(Box::new(sha1::Sha1::new())));
            }
            if options.digest_xxh64 {
                hashers.push(RefCell::new(Box::new(xxhash_rust::xxh64::Xxh64::new(0))));
            }
            Self { hashers }
        }

        #[instrument(name = "DigestManager::send", skip_all)]
        pub fn send(&self, data: Bytes) {
            for hasher in &self.hashers {
                hasher.borrow_mut().update(&data);
            }
        }

        #[instrument(name = "DigestManager::finish", skip_all)]
        pub fn finish(self) -> DigestResults {
            let mut results = DigestResults { crc32: None, md5: None, sha1: None, xxh64: None };
            for hasher in self.hashers {
                match hasher.borrow_mut().finalize() {
                    DigestResult::Crc32(v) => results.crc32 = Some(v),
                    DigestResult::Md5(v) => results.md5 = Some(v),
                    DigestResult::Sha1(v) => results.sha1 = Some(v),
                    DigestResult::Xxh64(v) => results.xxh64 = Some(v),
                }
            }
            results
        }
    }
}

#[cfg(all(feature = "threading", not(target_family = "wasm")))]
pub use multi_threaded::DigestManager;
#[cfg(not(all(feature = "threading", not(target_family = "wasm"))))]
pub use single_threaded::DigestManager;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DigestResult {
    Crc32(u32),
    Md5([u8; 16]),
    Sha1([u8; 20]),
    Xxh64(u64),
}

pub trait Hasher {
    #[cfg(all(feature = "threading", not(target_family = "wasm")))]
    const NAME: &'static str;

    #[cfg(all(feature = "threading", not(target_family = "wasm")))]
    fn new() -> Self;
    fn finalize(&mut self) -> DigestResult;
    fn update(&mut self, data: &[u8]);
}

impl Hasher for md5::Md5 {
    #[cfg(all(feature = "threading", not(target_family = "wasm")))]
    const NAME: &'static str = "MD5";

    #[cfg(all(feature = "threading", not(target_family = "wasm")))]
    fn new() -> Self { Digest::new() }

    fn finalize(&mut self) -> DigestResult {
        DigestResult::Md5(Digest::finalize_reset(self).into())
    }

    #[allow(unused_braces)] // https://github.com/rust-lang/rust/issues/116347
    #[instrument(name = "md5::Md5::update", skip_all)]
    fn update(&mut self, data: &[u8]) { Digest::update(self, data) }
}

impl Hasher for sha1::Sha1 {
    #[cfg(all(feature = "threading", not(target_family = "wasm")))]
    const NAME: &'static str = "SHA-1";

    #[cfg(all(feature = "threading", not(target_family = "wasm")))]
    fn new() -> Self { Digest::new() }

    fn finalize(&mut self) -> DigestResult {
        DigestResult::Sha1(Digest::finalize_reset(self).into())
    }

    #[allow(unused_braces)] // https://github.com/rust-lang/rust/issues/116347
    #[instrument(name = "sha1::Sha1::update", skip_all)]
    fn update(&mut self, data: &[u8]) { Digest::update(self, data) }
}

impl Hasher for crc32fast::Hasher {
    #[cfg(all(feature = "threading", not(target_family = "wasm")))]
    const NAME: &'static str = "CRC32";

    #[cfg(all(feature = "threading", not(target_family = "wasm")))]
    fn new() -> Self { crc32fast::Hasher::new() }

    fn finalize(&mut self) -> DigestResult {
        DigestResult::Crc32(crc32fast::Hasher::finalize(self.clone()))
    }

    #[allow(unused_braces)] // https://github.com/rust-lang/rust/issues/116347
    #[instrument(name = "crc32fast::Hasher::update", skip_all)]
    fn update(&mut self, data: &[u8]) { crc32fast::Hasher::update(self, data) }
}

impl Hasher for xxhash_rust::xxh64::Xxh64 {
    #[cfg(all(feature = "threading", not(target_family = "wasm")))]
    const NAME: &'static str = "XXH64";

    #[cfg(all(feature = "threading", not(target_family = "wasm")))]
    fn new() -> Self { xxhash_rust::xxh64::Xxh64::new(0) }

    fn finalize(&mut self) -> DigestResult {
        DigestResult::Xxh64(xxhash_rust::xxh64::Xxh64::digest(self))
    }

    #[allow(unused_braces)] // https://github.com/rust-lang/rust/issues/116347
    #[instrument(name = "xxhash_rust::xxh64::Xxh64::update", skip_all)]
    fn update(&mut self, data: &[u8]) { xxhash_rust::xxh64::Xxh64::update(self, data) }
}

pub struct DigestResults {
    pub crc32: Option<u32>,
    pub md5: Option<[u8; 16]>,
    pub sha1: Option<[u8; 20]>,
    pub xxh64: Option<u64>,
}

impl DiscFinalization {
    pub(crate) fn apply_digests(&mut self, results: &DigestResults) {
        self.crc32 = results.crc32;
        self.md5 = results.md5;
        self.sha1 = results.sha1;
        self.xxh64 = results.xxh64;
    }
}

impl NKitHeader {
    pub(crate) fn apply_digests(&mut self, results: &DigestResults) {
        self.crc32 = results.crc32;
        self.md5 = results.md5;
        self.sha1 = results.sha1;
        self.xxh64 = results.xxh64;
    }
}
