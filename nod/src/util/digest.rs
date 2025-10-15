use std::{thread, thread::JoinHandle};

use bytes::Bytes;
use crossbeam_channel::Sender;
use digest::Digest;
use tracing::instrument;

use crate::{
    common::HashBytes,
    io::nkit::NKitHeader,
    write::{DiscFinalization, ProcessOptions},
};

/// Hashes a byte slice with SHA-1.
#[instrument(skip_all)]
pub fn sha1_hash(buf: &[u8]) -> HashBytes {
    #[cfg(feature = "openssl")]
    {
        // The one-shot openssl::sha::sha1 ends up being much slower
        let mut hasher = openssl::sha::Sha1::new();
        hasher.update(buf);
        hasher.finish()
    }
    #[cfg(not(feature = "openssl"))]
    {
        use sha1::Digest;
        HashBytes::from(sha1::Sha1::digest(buf))
    }
}

/// Hashes a byte slice with XXH64.
#[allow(unused_braces)] // https://github.com/rust-lang/rust/issues/116347
#[instrument(skip_all)]
pub fn xxh64_hash(buf: &[u8]) -> u64 { xxhash_rust::xxh64::xxh64(buf, 0) }

pub type DigestThread = (Sender<Bytes>, JoinHandle<DigestResult>);

pub fn digest_thread<H>() -> DigestThread
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
            #[cfg(feature = "openssl")]
            threads.push(digest_thread::<openssl_util::HasherMD5>());
            #[cfg(not(feature = "openssl"))]
            threads.push(digest_thread::<md5::Md5>());
        }
        if options.digest_sha1 {
            #[cfg(feature = "openssl")]
            threads.push(digest_thread::<openssl_util::HasherSHA1>());
            #[cfg(not(feature = "openssl"))]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DigestResult {
    Crc32(u32),
    Md5([u8; 16]),
    Sha1([u8; 20]),
    Xxh64(u64),
}

pub trait Hasher {
    const NAME: &'static str;

    fn new() -> Self;
    fn finalize(self) -> DigestResult;
    fn update(&mut self, data: &[u8]);
}

impl Hasher for md5::Md5 {
    const NAME: &'static str = "MD5";

    fn new() -> Self { Digest::new() }

    fn finalize(self) -> DigestResult { DigestResult::Md5(Digest::finalize(self).into()) }

    #[allow(unused_braces)] // https://github.com/rust-lang/rust/issues/116347
    #[instrument(name = "md5::Md5::update", skip_all)]
    fn update(&mut self, data: &[u8]) { Digest::update(self, data) }
}

impl Hasher for sha1::Sha1 {
    const NAME: &'static str = "SHA-1";

    fn new() -> Self { Digest::new() }

    fn finalize(self) -> DigestResult { DigestResult::Sha1(Digest::finalize(self).into()) }

    #[allow(unused_braces)] // https://github.com/rust-lang/rust/issues/116347
    #[instrument(name = "sha1::Sha1::update", skip_all)]
    fn update(&mut self, data: &[u8]) { Digest::update(self, data) }
}

impl Hasher for crc32fast::Hasher {
    const NAME: &'static str = "CRC32";

    fn new() -> Self { crc32fast::Hasher::new() }

    fn finalize(self) -> DigestResult { DigestResult::Crc32(crc32fast::Hasher::finalize(self)) }

    #[allow(unused_braces)] // https://github.com/rust-lang/rust/issues/116347
    #[instrument(name = "crc32fast::Hasher::update", skip_all)]
    fn update(&mut self, data: &[u8]) { crc32fast::Hasher::update(self, data) }
}

impl Hasher for xxhash_rust::xxh64::Xxh64 {
    const NAME: &'static str = "XXH64";

    fn new() -> Self { xxhash_rust::xxh64::Xxh64::new(0) }

    fn finalize(self) -> DigestResult {
        DigestResult::Xxh64(xxhash_rust::xxh64::Xxh64::digest(&self))
    }

    #[allow(unused_braces)] // https://github.com/rust-lang/rust/issues/116347
    #[instrument(name = "xxhash_rust::xxh64::Xxh64::update", skip_all)]
    fn update(&mut self, data: &[u8]) { xxhash_rust::xxh64::Xxh64::update(self, data) }
}

#[cfg(feature = "openssl")]
mod openssl_util {
    use tracing::instrument;

    use super::{DigestResult, Hasher};

    pub type HasherMD5 = HashWrapper<MessageDigestMD5>;
    pub type HasherSHA1 = HashWrapper<MessageDigestSHA1>;

    pub struct HashWrapper<T>
    where T: MessageDigest
    {
        hasher: openssl::hash::Hasher,
        _marker: std::marker::PhantomData<T>,
    }

    impl<T> HashWrapper<T>
    where T: MessageDigest
    {
        fn new() -> Self {
            Self {
                hasher: openssl::hash::Hasher::new(T::new()).unwrap(),
                _marker: Default::default(),
            }
        }
    }

    pub trait MessageDigest {
        fn new() -> openssl::hash::MessageDigest;
    }

    pub struct MessageDigestMD5;

    impl MessageDigest for MessageDigestMD5 {
        fn new() -> openssl::hash::MessageDigest { openssl::hash::MessageDigest::md5() }
    }

    pub struct MessageDigestSHA1;

    impl MessageDigest for MessageDigestSHA1 {
        fn new() -> openssl::hash::MessageDigest { openssl::hash::MessageDigest::sha1() }
    }

    impl Hasher for HasherMD5 {
        const NAME: &'static str = "MD5";

        fn new() -> Self { Self::new() }

        fn finalize(mut self) -> DigestResult {
            DigestResult::Md5((*self.hasher.finish().unwrap()).try_into().unwrap())
        }

        #[allow(unused_braces)] // https://github.com/rust-lang/rust/issues/116347
        #[instrument(name = "openssl_util::HasherMD5::update", skip_all)]
        fn update(&mut self, data: &[u8]) { self.hasher.update(data).unwrap() }
    }

    impl Hasher for HasherSHA1 {
        const NAME: &'static str = "SHA-1";

        fn new() -> Self { Self::new() }

        fn finalize(mut self) -> DigestResult {
            DigestResult::Sha1((*self.hasher.finish().unwrap()).try_into().unwrap())
        }

        #[allow(unused_braces)] // https://github.com/rust-lang/rust/issues/116347
        #[instrument(name = "openssl_util::HasherSHA1::update", skip_all)]
        fn update(&mut self, data: &[u8]) { self.hasher.update(data).unwrap() }
    }
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
