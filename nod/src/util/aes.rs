use tracing::instrument;

use crate::{
    common::KeyBytes,
    disc::{
        SECTOR_SIZE,
        wii::{HASHES_SIZE, SECTOR_DATA_SIZE},
    },
    util::array_ref,
};

/// Encrypts data in-place using AES-128-CBC with the given key and IV.
pub fn aes_cbc_encrypt(key: &KeyBytes, iv: &KeyBytes, data: &mut [u8]) {
    use aes::cipher::{BlockModeEncrypt, KeyIvInit, block_padding::NoPadding};
    assert_eq!(data.len() % 16, 0);
    <cbc::Encryptor<aes::Aes128>>::new(key.into(), iv.into())
        .encrypt_padded::<NoPadding>(data, data.len())
        .unwrap();
}

/// Decrypts data in-place using AES-128-CBC with the given key and IV.
pub fn aes_cbc_decrypt(key: &KeyBytes, iv: &KeyBytes, data: &mut [u8]) {
    use aes::cipher::{BlockModeDecrypt, KeyIvInit, block_padding::NoPadding};
    assert_eq!(data.len() % 16, 0);
    <cbc::Decryptor<aes::Aes128>>::new(key.into(), iv.into())
        .decrypt_padded::<NoPadding>(data)
        .unwrap();
}

/// Decrypts data buffer-to-buffer using AES-128-CBC with the given key and IV.
pub fn aes_cbc_decrypt_b2b(key: &KeyBytes, iv: &KeyBytes, data: &[u8], out: &mut [u8]) {
    use aes::cipher::{BlockModeDecrypt, KeyIvInit, block_padding::NoPadding};
    assert_eq!(data.len() % 16, 0);
    assert_eq!(data.len(), out.len());
    <cbc::Decryptor<aes::Aes128>>::new(key.into(), iv.into())
        .decrypt_padded_b2b::<NoPadding>(data, out)
        .unwrap();
}

/// Encrypts a Wii partition sector in-place.
#[instrument(skip_all)]
pub fn encrypt_sector(out: &mut [u8; SECTOR_SIZE], key: &KeyBytes) {
    aes_cbc_encrypt(key, &[0u8; 16], &mut out[..HASHES_SIZE]);
    // Data IV from encrypted hash block
    let iv = *array_ref![out, 0x3D0, 16];
    aes_cbc_encrypt(key, &iv, &mut out[HASHES_SIZE..]);
}

/// Decrypts a Wii partition sector in-place.
#[instrument(skip_all)]
pub fn decrypt_sector(out: &mut [u8; SECTOR_SIZE], key: &KeyBytes) {
    // Data IV from encrypted hash block
    let iv = *array_ref![out, 0x3D0, 16];
    aes_cbc_decrypt(key, &[0u8; 16], &mut out[..HASHES_SIZE]);
    aes_cbc_decrypt(key, &iv, &mut out[HASHES_SIZE..]);
}

/// Decrypts a Wii partition sector buffer-to-buffer.
#[instrument(skip_all)]
pub fn decrypt_sector_b2b(data: &[u8; SECTOR_SIZE], out: &mut [u8; SECTOR_SIZE], key: &KeyBytes) {
    // Data IV from encrypted hash block
    let iv = *array_ref![data, 0x3D0, 16];
    aes_cbc_decrypt_b2b(key, &[0u8; 16], &data[..HASHES_SIZE], &mut out[..HASHES_SIZE]);
    aes_cbc_decrypt_b2b(key, &iv, &data[HASHES_SIZE..], &mut out[HASHES_SIZE..]);
}

/// Decrypts a Wii partition sector data (excluding hashes) buffer-to-buffer.
#[instrument(skip_all)]
pub fn decrypt_sector_data_b2b(
    data: &[u8; SECTOR_SIZE],
    out: &mut [u8; SECTOR_DATA_SIZE],
    key: &KeyBytes,
) {
    // Data IV from encrypted hash block
    let iv = *array_ref![data, 0x3D0, 16];
    aes_cbc_decrypt_b2b(key, &iv, &data[HASHES_SIZE..], out);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_cbc_known_vector() {
        // NIST SP 800-38A, F.2.1 (first block).
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let iv = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let plain = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];
        let cipher = [
            0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9,
            0x19, 0x7d,
        ];
        let mut data = plain;
        aes_cbc_encrypt(&key, &iv, &mut data);
        assert_eq!(data, cipher);
        aes_cbc_decrypt(&key, &iv, &mut data);
        assert_eq!(data, plain);
        aes_cbc_decrypt_b2b(&key, &iv, &cipher, &mut data);
        assert_eq!(data, plain);
    }
}
