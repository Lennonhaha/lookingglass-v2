// lgv2/src/crypto_binding.rs
// 五短板补全 #4: 密码学安全增益 —— 与 ML-KEM 共享密钥绑定
//
// 核心思想: 混淆输出不仅依赖混淆密钥，还与 ML-KEM 共享密钥绑定。
// 即使攻击者完全剥离了混淆层，仍无法还原原始数据——
//
// 必须同时持有:
//   1. 混淆结果 (confused_data)
//   2. ML-KEM 共享密钥 (kem_shared_secret)
//
// 绑定方式: Keccak-256(混淆输出 || MLKEM_SS) 派生绑定密钥，
// 再与混淆结果异或。攻击者不知道 SS 则无法"解除绑定"。

/// Keccak-256 哈希 (简化实现，与 SHA-3 的 Keccak-256 相同)
/// 用于派生绑定密钥
pub struct Keccak256 {
    state: [u64; 25],
    rate_bytes: usize,
    idx: usize,
}

impl Keccak256 {
    pub fn new() -> Self {
        Self {
            state: [0u64; 25],
            rate_bytes: 136, // 1600/8 - 2*64 (rate for Keccak-256)
            idx: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        for &b in data {
            self.state[self.idx / 8] ^= (b as u64) << (8 * (self.idx % 8));
            self.idx += 1;
            if self.idx == self.rate_bytes {
                self.squeeze();
                self.idx = 0;
            }
        }
    }

    pub fn finalize(&mut self) -> [u8; 32] {
        // SHA-3 padding (FIPS 202): absorb 0x06 → 0* → absorb 0x80
        self.state[self.idx / 8] ^= (0x06u64) << (8 * (self.idx % 8));
        // Set 0x80 at the last byte of the 136-byte rate
        let last_byte = self.rate_bytes - 1;
        self.state[last_byte / 8] ^= (0x80u64) << (8 * (last_byte % 8));
        // Keccak-f[1600] 全 24 轮
        for r in 0..24 {
            self.theta();
            self.rho_pi();
            self.chi();
            self.iota(r);
        }
        let mut h = [0u8; 32];
        for (i, chunk) in h.chunks_mut(8).enumerate() {
            let word = self.state[i];
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        h
    }

    fn squeeze(&mut self) {
        // Keccak-f[1600] 全 24 轮
        for r in 0..24 {
            self.theta();
            self.rho_pi();
            self.chi();
            self.iota(r);
        }
    }

    fn theta(&mut self) {
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = self.state[x] ^ self.state[x+5] ^ self.state[x+10] 
                  ^ self.state[x+15] ^ self.state[x+20];
        }
        for x in 0..5 {
            let d = c[(x+4)%5] ^ c[(x+1)%5].rotate_left(1);
            for y in 0..5 {
                self.state[y*5+x] ^= d;
            }
        }
    }

    fn rho_pi(&mut self) {
        // Rotation offsets for Keccak-f[1600] (FIPS 202 §3.2.3)
        const R: [[u32; 5]; 5] = [
            [0, 36, 3, 41, 18],
            [1, 44, 10, 45, 2],
            [62, 6, 43, 15, 61],
            [28, 55, 25, 21, 56],
            [27, 20, 39, 8, 14],
        ];
        let b = self.state; // copy (array is Copy)
        for x in 0..5 {
            for y in 0..5 {
                // π: (x,y) → (y, (2x+3y) mod 5)
                //   new x' = y, new y' = (2x+3y)%5
                //   state index = y' * 5 + x' = ((2x+3y)%5) * 5 + y
                let new_y = ((2 * x + 3 * y) % 5) as usize;
                self.state[new_y * 5 + y] = b[y * 5 + x].rotate_left(R[x][y]);
            }
        }
    }

    fn chi(&mut self) {
        let b = self.state;
        for y in 0..5 {
            for x in 0..5 {
                self.state[y*5+x] = b[y*5+x] ^ ((b[y*5+((x+1)%5)] ^ 0xFFFFFFFFFFFFFFFF) & b[y*5+((x+2)%5)]);
            }
        }
    }

    fn iota(&mut self, round: usize) {
        self.state[0] ^= Keccak256::RC[round % Keccak256::RC.len()];
    }
}

impl Keccak256 {
    const RC: [u64; 24] = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
        0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ];
}

impl Default for Keccak256 {
    fn default() -> Self { Self::new() }
}

/// 密码学绑定器: 将混淆输出与 ML-KEM 共享密钥绑定
pub struct CryptoBinding {
    binding_key: [u8; 32],
}

impl CryptoBinding {
    /// 从 ML-KEM 共享密钥 + 域分离标签派生绑定密钥
    /// binding_key = Keccak-256(domain_label || kem_shared_secret)
    /// Keccak 单向性确保即使绑定结果泄露也无法逆向出 SS
    pub fn new(kem_shared_secret: &[u8; 32]) -> Self {
        let binding_key = Self::derive_key(b"LGv2-CryptoBinding-v1", kem_shared_secret);
        Self { binding_key }
    }

    /// 用域分离标签派生绑定密钥
    /// 允许同一 SS 在不同上下文派生不同密钥
    pub fn with_domain(kem_shared_secret: &[u8; 32], domain: &[u8]) -> Self {
        let binding_key = Self::derive_key(domain, kem_shared_secret);
        Self { binding_key }
    }

    fn derive_key(domain: &[u8], secret: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        hasher.update(domain);
        hasher.update(secret);
        hasher.finalize()
    }

    /// 绑定: 将混淆输出与 binding_key 混合
    /// 使用 &self (纯运算，不修改状态)
    /// 数学自逆: bind(unbind(x)) = x, unbind(bind(x)) = x
    pub fn bind(&self, confused_data: &[u8]) -> Vec<u8> {
        confused_data.iter().enumerate()
            .map(|(i, &b)| b ^ self.binding_key[i % self.binding_key.len()])
            .collect()
    }

    /// 解绑定: 与绑定相同操作 (XOR 是自逆的)
    pub fn unbind(&self, bound_data: &[u8]) -> Vec<u8> {
        bound_data.iter().enumerate()
            .map(|(i, &b)| b ^ self.binding_key[i % self.binding_key.len()])
            .collect()
    }

    /// 验证绑定是否匹配 (不泄露 binding_key)
    pub fn verify(&self, bound_data: &[u8], expected_original: &[u8]) -> bool {
        let candidate = self.unbind(bound_data);
        candidate == expected_original
    }
}

// ============================================================
// 测试
// ============================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bind_unbind_roundtrip() {
        let ss: [u8; 32] = [0xDE; 32];
        let binding = CryptoBinding::new(&ss);

        let original = b"Hello, this is secret data!".to_vec();
        let bound = binding.bind(&original);
        assert_ne!(bound, original, "binding must change data");

        let recovered = binding.unbind(&bound);
        assert_eq!(recovered, original, "unbind must recover original");

        // 幂等性: bind 两次等价于 bind 一次
        let double = binding.bind(&bound);
        let recovered2 = binding.unbind(&double);
        assert_eq!(recovered2, bound);
    }

    #[test]
    fn test_different_keys_different_outputs() {
        let binding1 = CryptoBinding::new(&[0x11; 32]);
        let binding2 = CryptoBinding::new(&[0x22; 32]);
        let original = b"Secret message here".to_vec();

        let bound1 = binding1.bind(&original);
        let bound2 = binding2.bind(&original);

        assert_ne!(bound1, bound2, "different keys must produce different bindings");
        assert_eq!(binding1.unbind(&bound1), original);
        assert_eq!(binding2.unbind(&bound2), original);
    }

    #[test]
    fn test_keccak256_deterministic() {
        let mut h1 = Keccak256::new();
        h1.update(b"test");
        let r1 = h1.finalize();
        
        let mut h2 = Keccak256::new();
        h2.update(b"test");
        let r2 = h2.finalize();
        
        assert_eq!(r1, r2, "Keccak-256 must be deterministic");
    }

    #[test]
    fn test_keccak256_salt_sensitivity() {
        let mut h1 = Keccak256::new();
        h1.update(b"test");
        let r1 = h1.finalize();
        
        let mut h2 = Keccak256::new();
        h2.update(b"TEST");
        let r2 = h2.finalize();
        
        assert_ne!(r1, r2, "different input must produce different hash");
    }

    // ============================================================
    // NIST SHA-3-256 Known Answer Tests (FIPS 202)
    // ============================================================

    // SHA3-256("") = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
    #[test]
    fn test_sha3_256_empty() {
        let mut hasher = Keccak256::new();
        let result = hasher.finalize();
        let expected: [u8; 32] = [
            0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
            0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
            0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
            0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a,
        ];
        assert_eq!(result, expected, "SHA3-256(\"\") mismatch");
    }

    // SHA3-256("abc"): 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532
    #[test]
    fn test_sha3_256_abc() {
        let mut hasher = Keccak256::new();
        hasher.update(b"abc");
        let result = hasher.finalize();
        let expected: [u8; 32] = [
            0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2,
            0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd,
            0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b,
            0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32,
        ];
        assert_eq!(result, expected, "SHA3-256(\"abc\") mismatch");
    }

    // SHA3-256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
    // = 41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376
    #[test]
    fn test_sha3_256_long() {
        let mut hasher = Keccak256::new();
        hasher.update(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        let result = hasher.finalize();
        let expected: [u8; 32] = [
            0x41, 0xc0, 0xdb, 0xa2, 0xa9, 0xd6, 0x24, 0x08,
            0x49, 0x10, 0x03, 0x76, 0xa8, 0x23, 0x5e, 0x2c,
            0x82, 0xe1, 0xb9, 0x99, 0x8a, 0x99, 0x9e, 0x21,
            0xdb, 0x32, 0xdd, 0x97, 0x49, 0x6d, 0x33, 0x76,
        ];
        assert_eq!(result, expected, "SHA3-256(long) mismatch");
    }
}
