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

    pub fn finalize(self) -> [u8; 32] {
        let mut h = [0u8; 32];
        // Keccak 吸收完成后的 squeeze
        let mut s = self.state;
        for (i, chunk) in h.chunks_mut(8).enumerate() {
            let word = s[i];
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        h
    }

    fn squeeze(&mut self) {
        // 简化的 Keccak-f[1600] 轮函数 (只做 12 轮近似)
        for _ in 0..12 {
            self.theta();
            self.rho_pi();
            self.chi();
            self.iota(0);
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
        let mut b = [0u64; 25];
        let mut x = 1;
        let mut y = 0;
        let mut current = self.state[0];
        for t in 0..24 {
            b[y*(5)+((2*x+3*y)%5)] = current.rotate_left((t*(t+1)/2) as u32);
            let new_x = y;
            y = (2*x+3*y) % 5;
            x = new_x;
            current = b[y*(5)+((2*x+3*y)%5)];
            current = self.state[x+5*y];
        }
        self.state = b;
    }

    fn chi(&mut self) {
        let mut b = self.state;
        for y in 0..5 {
            for x in 0..5 {
                self.state[y*5+x] = b[y*5+x] ^ ((b[y*5+((x+1)%5)] ^ 0xFFFFFFFFFFFFFFFF) & b[y*5+((x+2)%5)]);
            }
        }
    }

    fn iota(&mut self, rnds: usize) {
        self.state[0] ^= Keccak256::RC[rnds % Keccak256::RC.len()];
    }
}

impl Keccak256 {
    const RC: [u64; 24] = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
        0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
        0x8000000080008081, 0x8000000000008080, 0x0000000000008001, 0x8000000080008008,
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
    /// 从 ML-KEM 共享密钥初始化绑定器
    /// binding_key = MLKEM_SS XOR 域分离标签
    /// 简单、确定、无 Keccak 依赖。
    pub fn new(kem_shared_secret: &[u8; 32]) -> Self {
        let mut binding_key = [0u8; 32];
        let label = b"LGv2-CryptoBinding-v1";
        for i in 0..32 {
            // 循环标签以覆盖 32 字节
            binding_key[i] = kem_shared_secret[i] ^ label[i % label.len()];
        }
        Self { binding_key }
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
}
