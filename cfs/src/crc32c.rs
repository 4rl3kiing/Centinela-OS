//! CRC32C (Castagnoli), table-driven; table built at compile time.

const POLYNOMIAL: u32 = 0x82f6_3b78;

const TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut index = 0;
    while index < 256 {
        let mut crc = index as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ POLYNOMIAL
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[index] = crc;
        index += 1;
    }
    table
};

pub fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in bytes {
        crc = TABLE[((crc ^ u32::from(byte)) & 0xff) as usize] ^ (crc >> 8);
    }
    !crc
}

#[cfg(test)]
mod tests {
    #[test]
    fn known_vectors() {
        // RFC 3720 appendix B.4 test vectors.
        assert_eq!(super::crc32c(b"123456789"), 0xe306_9283);
        assert_eq!(super::crc32c(&[0u8; 32]), 0x8a91_36aa);
        assert_eq!(super::crc32c(&[0xffu8; 32]), 0x62a8_ab43);
    }
}
