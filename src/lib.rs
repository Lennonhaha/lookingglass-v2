// lib.rs — LG v2.1/v2.2 混淆引擎 + 五短板补全
//
// 五短板补全模块:
//   dynamic_path   : 防自动化攻击 (状态依赖动态路径选择)
//   secure_cleanup : 内存 Dump 防护 (运行时零化 RAII)
//   control_flow   : 商业级混淆 (控制流平坦化 + 不透明谓词)
//   crypto_binding : 密码学增益 (ML-KEM 共享密钥绑定)
//
// 原有 API 完全保持不变，新增 API 带 "_ex" 后缀

use wasm_bindgen::prelude::*;

// ============================================================
// 原有七层混淆核心 (完全不变，保持 10 项交叉验证通过)
// ============================================================

const NUM_LAYERS: usize = 7;

// ---- AES S-box ----
static SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

static INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
    0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
    0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
    0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
    0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
    0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
    0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
    0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
    0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
    0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
    0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
    0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

// ---- xorshift64 ----
pub struct XorShift64(pub u64);

impl XorShift64 {
    pub fn new(seed: u64) -> Self { Self(if seed == 0 { 1 } else { seed }) }
    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13; x ^= x >> 7; x ^= x << 17; self.0 = x; x
    }
    pub fn next_u8(&mut self) -> u8 { (self.next() & 0xFF) as u8 }
}

// ---- seed derivation ----
pub fn layer_seed(base: u64, idx: usize) -> u64 {
    let mut s = base ^ ((idx as u64 + 1).wrapping_mul(0x9E3779B97F4A7C15));
    s ^= s >> 30; s = s.wrapping_mul(0xBF58476D1CE4E5B9); s ^= s >> 27;
    s = s.wrapping_mul(0x94D049BB133111EB); s ^= s >> 31; s
}

// ---- layer seeds ----
pub struct LayerSeeds {
    pub off1: [u64; NUM_LAYERS],
    pub off2: [u64; NUM_LAYERS],
}

impl LayerSeeds {
    pub fn new(seed: u64) -> Self {
        let mut off1 = [0u64; NUM_LAYERS];
        let mut off2 = [0u64; NUM_LAYERS];
        for li in 0..NUM_LAYERS {
            let mut rng = XorShift64::new(layer_seed(seed, li + NUM_LAYERS));
            off1[li] = rng.next();
            off2[li] = rng.next();
        }
        Self { off1, off2 }
    }
}

// ---- confuse/deconfuse a single chunk —— 可变深度 + 预分配复用 ----
fn confuse_chunk_depth(chunk: &mut [u8], seed: u64, seeds: &LayerSeeds, depth: usize) {
    let n = chunk.len();
    let layers = depth.clamp(1, NUM_LAYERS);
    let mut perm = vec![0usize; n];
    let mut tmp = vec![0u8; n];
    let mut off1 = vec![0u8; n];
    let mut off2 = vec![0u8; n];
    for li in 0..layers {
        let mut rng = XorShift64::new(layer_seed(seed, li));
        for i in 0..n { perm[i] = i; }
        for i in (1..n).rev() {
            let j = (rng.next() % (i as u64 + 1)) as usize;
            perm.swap(i, j);
        }
        let mut rng1 = XorShift64::new(seeds.off1[li]);
        let mut rng2 = XorShift64::new(seeds.off2[li]);
        for i in 0..n { off1[i] = rng1.next_u8(); }
        for i in 0..n { off2[i] = rng2.next_u8(); }
        for i in 0..n { tmp[i] = chunk[i] ^ off1[i]; }
        // fused: permute + XOR-off2 + S-box in two passes
        for i in 0..n {
            chunk[perm[i]] = SBOX[(tmp[i] ^ off2[perm[i]]) as usize];
        }
    }
}

fn deconfuse_chunk_depth(chunk: &mut [u8], seed: u64, seeds: &LayerSeeds, depth: usize) {
    let n = chunk.len();
    let layers = depth.clamp(1, NUM_LAYERS);
    let mut perm = vec![0usize; n];
    let mut inv_perm = vec![0usize; n];
    let mut tmp = vec![0u8; n];
    let mut off1 = vec![0u8; n];
    let mut off2 = vec![0u8; n];
    for li in (0..layers).rev() {
        // fused: INV_SBOX + generate off1/off2 in parallel
        let mut rng = XorShift64::new(layer_seed(seed, li));
        for i in 0..n { perm[i] = i; }
        for i in (1..n).rev() {
            let j = (rng.next() % (i as u64 + 1)) as usize;
            perm.swap(i, j);
        }
        for i in 0..n { inv_perm[perm[i]] = i; }
        let mut rng1 = XorShift64::new(seeds.off1[li]);
        let mut rng2 = XorShift64::new(seeds.off2[li]);
        for i in 0..n { off1[i] = rng1.next_u8(); }
        for i in 0..n { off2[i] = rng2.next_u8(); }
        // fused: inv-S-box + xor-off2 + inv-permute + xor-off1
        for i in 0..n {
            let val = INV_SBOX[chunk[i] as usize] ^ off2[i];
            tmp[inv_perm[i]] = val;
        }
        for i in 0..n { chunk[i] = tmp[i] ^ off1[i]; }
    }
}

fn confuse_full(data: &mut [u8], seed: u64) {
    let seeds = LayerSeeds::new(seed);
    confuse_chunk_depth(data, seed, &seeds, NUM_LAYERS);
}

fn deconfuse_full(data: &mut [u8], seed: u64) {
    let seeds = LayerSeeds::new(seed);
    deconfuse_chunk_depth(data, seed, &seeds, NUM_LAYERS);
}

// ============================================================
// 五短板补全模块
// ============================================================

pub mod dynamic_path;
pub mod control_flow;
pub mod crypto_binding;
pub mod secure_cleanup;

use crypto_binding::CryptoBinding;
use secure_cleanup::SecureBuffer;

// ============================================================
// WASM 公开 API (原有 — 完全不变)
// ============================================================

#[wasm_bindgen]
pub fn lgv2_confuse(data: &[u8], seed: u64) -> Vec<u8> {
    if data.is_empty() { return vec![]; }
    let mut result = data.to_vec();
    confuse_full(&mut result, seed);
    result
}

/// lgv2_confuse_d: 可变深度的混淆 (depth: 1..=7, 默认 7)
#[wasm_bindgen]
pub fn lgv2_confuse_d(data: &[u8], seed: u64, depth: usize) -> Vec<u8> {
    if data.is_empty() { return vec![]; }
    let seeds = LayerSeeds::new(seed);
    let mut result = data.to_vec();
    confuse_chunk_depth(&mut result, seed, &seeds, depth);
    result
}

#[wasm_bindgen]
pub fn lgv2_deconfuse(data: &[u8], seed: u64) -> Vec<u8> {
    if data.is_empty() { return vec![]; }
    let mut result = data.to_vec();
    deconfuse_full(&mut result, seed);
    result
}

/// lgv2_deconfuse_d: 可变深度的解混淆 (depth 必须与混淆时一致)
#[wasm_bindgen]
pub fn lgv2_deconfuse_d(data: &[u8], seed: u64, depth: usize) -> Vec<u8> {
    if data.is_empty() { return vec![]; }
    let seeds = LayerSeeds::new(seed);
    let mut result = data.to_vec();
    deconfuse_chunk_depth(&mut result, seed, &seeds, depth);
    result
}

// ============================================================
// WASM 公开 API (五短板增强版)
// ============================================================

/// 增强混淆: session 差异化 + 安全零化 + 可变深度
/// depth: 1..=7, 默认 7; 值越大混淆越强但越慢
#[wasm_bindgen]
pub fn lgv2_confuse_ex(data: &[u8], seed: u64, session_key: u64, depth: usize) -> Vec<u8> {
    if data.is_empty() { return vec![]; }
    let mut buf = SecureBuffer::from_slice(data);
    let combined_seed = seed.wrapping_add(session_key);
    confuse_chunk_depth(buf.get_mut(), combined_seed, &LayerSeeds::new(combined_seed), depth);
    let result = buf.get().to_vec();
    buf.zeroize();
    result
}

/// 增强解混淆: session 差异化 + 可变深度 (depth 必须与混淆时一致)
#[wasm_bindgen]
pub fn lgv2_deconfuse_ex(data: &[u8], seed: u64, session_key: u64, depth: usize) -> Vec<u8> {
    if data.is_empty() { return vec![]; }
    let mut buf = SecureBuffer::from_slice(data);
    let combined_seed = seed.wrapping_add(session_key);
    deconfuse_chunk_depth(buf.get_mut(), combined_seed, &LayerSeeds::new(combined_seed), depth);
    let result = buf.get().to_vec();
    buf.zeroize();
    result
}

/// 密码学绑定: 将混淆输出与 ML-KEM 共享密钥绑定
/// kem_ss: 32 字节 ML-KEM 共享密钥
/// 返回: 混淆结果 XOR Keccak-256(binding_label || MLKEM_SS)
#[wasm_bindgen]
pub fn lgv2_bind_kem(data: &[u8], kem_ss: &[u8]) -> Vec<u8> {
    if data.is_empty() || kem_ss.len() != 32 { return vec![]; }
    let mut ss = [0u8; 32];
    ss.copy_from_slice(&kem_ss[..32]);
    let binding = CryptoBinding::new(&ss);
    binding.bind(data)
}

/// 密码学解绑: 使用相同 ML-KEM 共享密钥解除绑定
#[wasm_bindgen]
pub fn lgv2_unbind_kem(data: &[u8], kem_ss: &[u8]) -> Vec<u8> {
    if data.is_empty() || kem_ss.len() != 32 { return vec![]; }
    let mut ss = [0u8; 32];
    ss.copy_from_slice(&kem_ss[..32]);
    let binding = CryptoBinding::new(&ss);
    binding.unbind(data)
}

/// 端到端安全混淆: 混乱 + ML-KEM 绑定 + 可变深度
#[wasm_bindgen]
pub fn lgv2_confuse_full(data: &[u8], seed: u64, session_key: u64, kem_ss: &[u8], depth: usize) -> Vec<u8> {
    if data.is_empty() || kem_ss.len() != 32 { return vec![]; }
    let mut buf = SecureBuffer::from_slice(data);
    let combined_seed = seed.wrapping_add(session_key);
    confuse_chunk_depth(buf.get_mut(), combined_seed, &LayerSeeds::new(combined_seed), depth);
    let mut ss = [0u8; 32];
    ss.copy_from_slice(&kem_ss[..32]);
    let binding = CryptoBinding::new(&ss);
    let result = binding.bind(buf.get());
    buf.zeroize();
    result
}

/// 端到端安全解绑: ML-KEM 解绑 + 解混淆 + 可变深度
#[wasm_bindgen]
pub fn lgv2_deconfuse_full(data: &[u8], seed: u64, session_key: u64, kem_ss: &[u8], depth: usize) -> Vec<u8> {
    if data.is_empty() || kem_ss.len() != 32 { return vec![]; }
    let mut ss = [0u8; 32];
    ss.copy_from_slice(&kem_ss[..32]);
    let binding = CryptoBinding::new(&ss);
    let unbound = binding.unbind(data);
    if unbound.is_empty() { return vec![]; }
    let mut buf = SecureBuffer::from_slice(&unbound);
    let combined_seed = seed.wrapping_add(session_key);
    deconfuse_chunk_depth(buf.get_mut(), combined_seed, &LayerSeeds::new(combined_seed), depth);
    let result = buf.get().to_vec();
    buf.zeroize();
    result
}

/// 获取库版本信息
#[wasm_bindgen]
pub fn lgv2_version() -> String {
    "LG v2.2.2 (可变深度 + fused pass)".to_string()
}

// ============================================================
// 单元测试 (原有 10 项保持不变)
// ============================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compare_with_python_100b() {
        let data: Vec<u8> = (0..100).map(|i| (i * 7) as u8).collect();
        let confused = lgv2_confuse(&data, 0x1234);
        let expected_first8 = vec![215, 243, 99, 104, 54, 216, 205, 254];
        assert_eq!(&confused[..8], &expected_first8[..], "100B first 8 bytes must match Python");
    }

    #[test]
    fn test_roundtrip_100b() {
        let data: Vec<u8> = (0..100).map(|i| (i * 7) as u8).collect();
        let confused = lgv2_confuse(&data, 0x1234);
        let restored = lgv2_deconfuse(&confused, 0x1234);
        assert_eq!(data, restored, "round-trip 100B failed");
    }

    #[test]
    fn test_roundtrip_840b() {
        let data: Vec<u8> = (0..840).map(|i| (i ^ 0xAA) as u8).collect();
        let confused = lgv2_confuse(&data, 0xDEADBEEF);
        let restored = lgv2_deconfuse(&confused, 0xDEADBEEF);
        assert_eq!(data, restored, "round-trip 840B failed");
    }

    #[test]
    fn test_roundtrip_2000b() {
        let data: Vec<u8> = (0..2000).map(|i| (i & 0xFF) as u8).collect();
        let confused = lgv2_confuse(&data, 0xCAFE);
        let restored = lgv2_deconfuse(&confused, 0xCAFE);
        assert_eq!(data, restored, "round-trip 2000B failed");
    }

    #[test]
    fn test_roundtrip_4b() {
        let data = vec![0x01, 0x02, 0x03, 0x04];
        let confused = lgv2_confuse(&data, 42);
        let restored = lgv2_deconfuse(&confused, 42);
        assert_eq!(data, restored, "round-trip 4B failed");
    }

    #[test]
    fn test_roundtrip_1b() {
        let data = vec![0xAA];
        let confused = lgv2_confuse(&data, 99);
        let restored = lgv2_deconfuse(&confused, 99);
        assert_eq!(data, restored, "round-trip 1B failed");
    }

    #[test]
    fn test_deterministic() {
        let data: Vec<u8> = (0..100).map(|i| i as u8).collect();
        let r1 = lgv2_confuse(&data, 42);
        let r2 = lgv2_confuse(&data, 42);
        assert_eq!(r1, r2, "same seed must produce same output");
    }

    #[test]
    fn test_seed_sensitivity() {
        let data: Vec<u8> = (0..100).map(|i| i as u8).collect();
        let r1 = lgv2_confuse(&data, 42);
        let r2 = lgv2_confuse(&data, 43);
        assert_ne!(r1, r2, "different seed must produce different output");
    }

    #[test]
    fn test_empty_input() {
        let data: Vec<u8> = vec![];
        let confused = lgv2_confuse(&data, 0);
        assert_eq!(confused.len(), 0);
    }

    // ---- 可变深度测试 ----

    #[test]
    fn test_depth_roundtrip() {
        let data: Vec<u8> = (0..100).map(|i| i as u8).collect();
        for d in 1..=NUM_LAYERS {
            let confused = lgv2_confuse_d(&data, 0x1234, d);
            let restored = lgv2_deconfuse_d(&confused, 0x1234, d);
            assert_eq!(data, restored, "depth={} roundtrip failed", d);
        }
    }

    #[test]
    fn test_depth_7_equals_default() {
        let data: Vec<u8> = (0..100).map(|i| i as u8).collect();
        let c7 = lgv2_confuse_d(&data, 0x1234, 7);
        let cdef = lgv2_confuse(&data, 0x1234);
        assert_eq!(c7, cdef, "depth=7 must equal default");
    }

    #[test]
    fn test_different_depths_differ() {
        let data: Vec<u8> = (0..100).map(|i| i as u8).collect();
        let c1 = lgv2_confuse_d(&data, 0x1234, 3);
        let c2 = lgv2_confuse_d(&data, 0x1234, 5);
        assert_ne!(c1, c2, "different depths must produce different output");
    }

    // ---- 五短板增强测试 ----

    #[test]
    fn test_confuse_ex_roundtrip() {
        let data: Vec<u8> = (0..100).map(|i| i as u8).collect();
        let confused = lgv2_confuse_ex(&data, 0x1234, 0xDEAD, 7);
        let restored = lgv2_deconfuse_ex(&confused, 0x1234, 0xDEAD, 7);
        assert_eq!(data, restored, "confuse_ex roundtrip must recover");
    }

    #[test]
    fn test_confuse_ex_different_session_differs() {
        let data: Vec<u8> = (0..100).map(|i| i as u8).collect();
        let c1 = lgv2_confuse_ex(&data, 0x1234, 0x1111, 7);
        let c2 = lgv2_confuse_ex(&data, 0x1234, 0x2222, 7);
        assert_ne!(c1, c2, "different session keys must produce different output");
    }

    #[test]
    fn test_bind_unbind_roundtrip() {
        let data: Vec<u8> = (0..100).map(|i| i as u8).collect();
        let ss: Vec<u8> = (0..32).map(|i| i as u8).collect();
        let bound = lgv2_bind_kem(&data, &ss);
        let unbound = lgv2_unbind_kem(&bound, &ss);
        assert_eq!(data, unbound, "bind/unbind must be self-inverse");
    }

    #[test]
    fn test_full_confuse_deconfuse() {
        let data: Vec<u8> = (0..100).map(|i| i as u8).collect();
        let ss: Vec<u8> = (0..32).map(|i| 0x42u8).collect();
        let confused = lgv2_confuse_full(&data, 0x1234, 0xDEAD, &ss, 7);
        let restored = lgv2_deconfuse_full(&confused, 0x1234, 0xDEAD, &ss, 7);
        assert_eq!(data, restored, "full confuse/deconfuse must recover");
    }

    #[test]
    fn test_full_confuse_changes_output() {
        let data: Vec<u8> = (0..100).map(|i| i as u8).collect();
        let ss: Vec<u8> = vec![0x42u8; 32];
        let plain_confused = lgv2_confuse(&data, 0x1234);
        let full_confused = lgv2_confuse_full(&data, 0x1234, 0xDEAD, &ss, 7);
        assert_ne!(plain_confused, full_confused, "full confuse must differ from plain confuse");
    }
}
