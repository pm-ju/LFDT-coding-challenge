pub(crate) fn expand(block: &[u8], len: usize) -> Vec<u8> {
    debug_assert!(!block.is_empty());

    let mut out = Vec::with_capacity(len);
    let full = len / block.len();
    let tail = len % block.len();

    for _ in 0..full {
        out.extend_from_slice(block);
    }
    out.extend_from_slice(&block[..tail]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_multiple() {
        assert_eq!(
            expand(&[0xAA, 0xBB], 6),
            [0xAA, 0xBB, 0xAA, 0xBB, 0xAA, 0xBB]
        );
    }

    #[test]
    fn with_remainder() {
        assert_eq!(expand(&[1, 2, 3], 5), [1, 2, 3, 1, 2]);
    }

    #[test]
    fn shorter_than_block() {
        assert_eq!(expand(&[10, 20, 30, 40], 2), [10, 20]);
    }

    #[test]
    fn zero_length() {
        assert!(expand(&[0xFF], 0).is_empty());
    }

    #[test]
    fn single_byte_block() {
        assert_eq!(expand(&[0x42], 4), [0x42; 4]);
    }
}
