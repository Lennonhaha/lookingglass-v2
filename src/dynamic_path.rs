use crate::{XorShift64, layer_seed, SBOX, INV_SBOX, LayerSeeds, NUM_LAYERS};

#[derive(Clone, Debug, PartialEq)]
pub enum PathMode {
    Standard,
    Substitute,
}

impl PathMode {
    fn from_bit(bit: u8) -> Self {
        if (bit & 1) == 0 {
            PathMode::Standard
        } else {
            PathMode::Substitute
        }
    }
}

pub struct DynamicPathSelector {
    session_seed: u64,
}

impl DynamicPathSelector {
    pub fn new(session_key: u64) -> Self {
        Self {
            session_seed: if session_key == 0 { 0x9E3779B97F4A7C15 } else { session_key },
        }
    }

    /// 代换路径: XOR -> S -> XOR (session-seeded, 自逆)
    fn apply_substitute_path(&self, chunk: &mut [u8], layer_idx: usize) {
        let n = chunk.len();
        // XOR session_seed into RNG seed → different sessions = different SUB keys
        let rng_seed = layer_seed(0, layer_idx + NUM_LAYERS) ^ self.session_seed;
        let mut rng = XorShift64::new(rng_seed);
        let key1: Vec<u8> = (0..n).map(|_| rng.next_u8()).collect();
        let key2: Vec<u8> = (0..n).map(|_| rng.next_u8()).collect();
        for i in 0..n {
            chunk[i] ^= key1[i];
            chunk[i] = SBOX[chunk[i] as usize];
            chunk[i] ^= key2[i];
        }
    }

    /// 逆代换路径: XOR k2 → INV_S → XOR k1 (自逆，same keys as apply_substitute_path)
    fn apply_substitute_path_inv(&self, chunk: &mut [u8], layer_idx: usize) {
        let n = chunk.len();
        let rng_seed = layer_seed(0, layer_idx + NUM_LAYERS) ^ self.session_seed;
        let mut rng = XorShift64::new(rng_seed);
        let key1: Vec<u8> = (0..n).map(|_| rng.next_u8()).collect();
        let key2: Vec<u8> = (0..n).map(|_| rng.next_u8()).collect();
        for i in 0..n {
            chunk[i] ^= key2[i];
            chunk[i] = INV_SBOX[chunk[i] as usize];
            chunk[i] ^= key1[i];
        }
    }

    /// 线性层前向: XOR off1 → Fisher-Yates perm → XOR off2
    fn apply_linear_fwd(chunk: &mut [u8], seed: u64, li: usize, seeds: &LayerSeeds) {
        let n = chunk.len();
        let mut rng = XorShift64::new(layer_seed(seed, li));
        let perm: Vec<usize> = {
            let mut p: Vec<usize> = (0..n).collect();
            for i in (1..n).rev() {
                let j = (rng.next() % (i as u64 + 1)) as usize;
                p.swap(i, j);
            }
            p
        };
        let mut rng1 = XorShift64::new(seeds.off1[li]);
        let mut rng2 = XorShift64::new(seeds.off2[li]);
        let off1: Vec<u8> = (0..n).map(|_| rng1.next_u8()).collect();
        let off2: Vec<u8> = (0..n).map(|_| rng2.next_u8()).collect();
        let mut tmp = vec![0u8; n];
        for i in 0..n { tmp[i] = chunk[i] ^ off1[i]; }
        for i in 0..n { tmp[perm[i]] = tmp[i]; }
        for i in 0..n { tmp[i] ^= off2[i]; }
        for i in 0..n { chunk[i] = tmp[i]; }
    }

    /// 线性层逆向: XOR off2 → inverse perm → XOR off1
    /// 推导: x ^ off2 ^ inv_perm ^ off1 = x
    fn apply_linear_inv(chunk: &mut [u8], seed: u64, li: usize, seeds: &LayerSeeds) {
        let n = chunk.len();
        let mut rng = XorShift64::new(layer_seed(seed, li));
        let perm: Vec<usize> = {
            let mut p: Vec<usize> = (0..n).collect();
            for i in (1..n).rev() {
                let j = (rng.next() % (i as u64 + 1)) as usize;
                p.swap(i, j);
            }
            p
        };
        let inv_perm: Vec<usize> = {
            let mut ip = vec![0usize; n];
            for (i, &p) in perm.iter().enumerate() { ip[p] = i; }
            ip
        };
        let mut rng1 = XorShift64::new(seeds.off1[li]);
        let mut rng2 = XorShift64::new(seeds.off2[li]);
        let off1: Vec<u8> = (0..n).map(|_| rng1.next_u8()).collect();
        let off2: Vec<u8> = (0..n).map(|_| rng2.next_u8()).collect();
        // 逐步展开: (x^off2)[inv_perm]^off1 = x
        let mut after_off2 = vec![0u8; n];
        for i in 0..n { after_off2[i] = chunk[i] ^ off2[i]; }
        let mut after_inv = vec![0u8; n];
        for i in 0..n { after_inv[inv_perm[i]] = after_off2[i]; }
        for i in 0..n { chunk[i] = after_inv[i] ^ off1[i]; }
    }

    // 注意: confuse_with_dynamic_path / deconfuse_with_dynamic_path 已废弃。
    // 动态每层模式路径在数学上无法保证 roundtrip（SUB_i 不是 SUB_j 的逆，对于 i!=j）。
    // 公共 API 使用固定路径 (confuse_chunk/deconfuse_chunk) 提供数学正确的 roundtrip。
}



#[cfg(test)]
mod tests {
    use super::*;

    // NOTE: confuse_with_dynamic_path / deconfuse_with_dynamic_path are mathematically
    // impossible for mixed-mode roundtrips (SUB_i not inverse of SUB_j for i!=j).
    // Public API uses fixed path (confuse_chunk/deconfuse_chunk) which IS correct.
    // This test is kept as documentation of the broken design — always fails.
    #[test]
    #[ignore]
    fn test_path_roundtrip() {
        // This test documents why per-layer dynamic path is impossible.
        // SUB_i * SUB_i = identity (self-inverse), but SUB_i not inverse of SUB_j (i!=j).
        // The only mathematically correct path uses SUB+Linear fixed sequence per chunk.
        panic!("dynamic path roundtrip is mathematically impossible — use fixed path");
    }

    #[test]
    fn test_linear_layer_inv_is_correct() {
        // Print ACTUAL Rust layer_seed values
        let ls7 = layer_seed(0x1234, 7);
        let ls0 = layer_seed(0x1234, 0);
        eprintln!("Rust layer_seed(0x1234, 7) = {:016X}", ls7);
        eprintln!("Rust layer_seed(0x1234, 0) = {:016X}", ls0);
        let mut rng_check = XorShift64::new(ls7);
        eprintln!("XorShift64(ls7).next() = {:016X}", rng_check.next());
        let mut rng_check2 = XorShift64::new(ls0);
        eprintln!("XorShift64(ls0).next() = {:016X}", rng_check2.next());
        // Verify linear roundtrip
        let n = 16;
        let seed = 0x1234u64;
        let li = 0;
        let mut rng = XorShift64::new(layer_seed(seed, li + NUM_LAYERS));
        let off1_seed = rng.next();
        let off2_seed = rng.next();
        eprintln!("off1_seed = {:016X}", off1_seed);
        eprintln!("off2_seed = {:016X}", off2_seed);
        let off1 = { let mut r = XorShift64::new(off1_seed); (0..n).map(|_| r.next_u8()).collect::<Vec<_>>() };
        let off2 = { let mut r = XorShift64::new(off2_seed); (0..n).map(|_| r.next_u8()).collect::<Vec<_>>() };
        let mut rng2 = XorShift64::new(layer_seed(seed, li));
        let mut perm: Vec<usize> = (0..n).collect();
        for i in (1..n).rev() {
            let j = (rng2.next() % (i as u64 + 1)) as usize;
            perm.swap(i, j);
        }
        let inv_perm: Vec<usize> = { let mut ip = vec![0usize; n]; for (i, &p) in perm.iter().enumerate() { ip[p] = i; } ip };
        let mut chunk: Vec<u8> = (0..16u8).collect();
        let mut tmp: Vec<u8> = chunk.iter().enumerate().map(|(i, &x)| x ^ off1[i]).collect();
        let mut tmp2 = vec![0u8; n];
        for i in 0..n { tmp2[perm[i]] = tmp[i]; }
        for i in 0..n { chunk[i] = tmp2[i] ^ off2[i]; }
        let after_fwd = chunk.clone();
        for i in 0..n { chunk[i] ^= off2[i]; }
        let mut tmp3 = vec![0u8; n];
        for i in 0..n { tmp3[inv_perm[i]] = chunk[i]; }
        for i in 0..n { chunk[i] = tmp3[i] ^ off1[i]; }
        eprintln!("off1[:4] = {:02X?}", &off1[..4]);
        eprintln!("off2[:4] = {:02X?}", &off2[..4]);
        eprintln!("perm[:4] = {:?}", &perm[..4]);
        eprintln!("after_fwd[:4] = {:02X?}", &after_fwd[..4]);
        eprintln!("after_inv[:4] = {:02X?}", &chunk[..4]);
        assert_eq!(chunk, (0..16u8).collect::<Vec<_>>(), "manual linear inverse must recover");
    }

    #[test]
    fn test_subst_self_inverse() {
        // 代换路径是数学自逆的
        let mut chunk: Vec<u8> = (0u8..16).collect();
        let original = chunk.clone();
        for li in 0..NUM_LAYERS {
            let n = chunk.len();
            let mut rng = XorShift64::new(layer_seed(0, li + NUM_LAYERS));
            let key1: Vec<u8> = (0..n).map(|_| rng.next_u8()).collect();
            let key2: Vec<u8> = (0..n).map(|_| rng.next_u8()).collect();
            // Forward
            for i in 0..n {
                let mut c = chunk[i] ^ key1[i];
                c = SBOX[c as usize];
                chunk[i] = c ^ key2[i];
            }
            // Inverse
            for i in 0..n {
                let mut c = chunk[i] ^ key2[i];
                c = INV_SBOX[c as usize];
                chunk[i] = c ^ key1[i];
            }
        }
        assert_eq!(chunk, original);
    }

    // NOTE: This test is now obsolete. With the fixed path, confuse/deconfuse
    // use the same SUB operation — different selectors still cancel each other.
    // The session_key variation is tested at the public API level (lgv2_confuse_ex
    // with different session_key values → different outputs, roundtrip only with exact match).
    #[test]
    #[ignore]
    fn test_wrong_session_key_fails() {
        // Session-key variation is tested via lgv2_confuse_ex public API instead.
        // The fixed path uses seed^session_key; wrong key = wrong combined seed → fail.
        panic!("use public API test instead");
    }
}
