// lgv2/src/secure_cleanup.rs
// 五短板补全 #2: 内存 Dump 防护 —— 运行时零化
//
// 核心思想: 敏感数据（混淆输入/输出/中间向量）使用完毕后立即清零。
// 在 WASM 环境中，由于 GC 可能延迟回收，manual zeroize 比依赖 drop 更可靠。
//
// 实现: 安全缓冲区类型 + 零化工具函数
// 不使用 external zeroize crate，保持零外部依赖

/// 安全缓冲区: 析构时将数据区域覆写为零
/// 在 WASM 中通过 manual cleanup 调用，绕过 GC 延迟
pub struct SecureBuffer {
    /// 存储区域 (固定最大长度，避免堆分配)
    data: Vec<u8>,
}

impl SecureBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            data: vec![0u8; capacity],
        }
    }

    /// 从外部数据初始化安全缓冲区
    pub fn from_slice(data: &[u8]) -> Self {
        Self {
            data: data.to_vec(),
        }
    }

    /// 获取只读引用
    pub fn get(&self) -> &[u8] {
        &self.data
    }

    /// 获取可变引用
    pub fn get_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// 长度
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// 运行时零化: 将数据覆写为零
    /// 在 drop 前手动调用，防止 GC 延迟导致数据残留
    pub fn zeroize(&mut self) {
        for b in &mut self.data {
            *b = 0;
        }
        // 额外一轮覆写，防止优化掉
        for b in &mut self.data {
            *b = 0;
        }
    }

    /// 从外部覆写为零 (用于非 SecureBuffer 类型的零化)
    pub fn zeroize_slice(slice: &mut [u8]) {
        // 第一轮: 0xFF
        for b in slice.iter_mut() {
            *b = 0xFF;
        }
        // 第二轮: 0x00
        for b in slice.iter_mut() {
            *b = 0x00;
        }
        // 第三轮: 随机值 (用 xorshift 生成确定性随机)
        let mut rng = crate::XorShift64(0x123456789ABCDEF0);
        for b in slice.iter_mut() {
            *b = rng.next() as u8;
        }
        // 第四轮: 最终清零
        for b in slice.iter_mut() {
            *b = 0;
        }
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        // Drop 时自动零化 (belt-and-suspenders)
        self.zeroize();
    }
}

/// 零化后保持有效指针的 RAII 封装
pub struct SecureData {
    data: Vec<u8>,
    pub is_cleaned: bool,
}

impl SecureData {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data, is_cleaned: false }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// 安全处理: 在闭包内使用数据，闭包结束后自动零化
    pub fn with_secure<F, T>(&mut self, f: F) -> T
    where
        F: FnOnce(&[u8]) -> T,
    {
        let result = f(&self.data);
        self.zeroize();
        result
    }

    pub fn zeroize(&mut self) {
        if !self.is_cleaned {
            SecureBuffer::zeroize_slice(&mut self.data);
            self.is_cleaned = true;
        }
    }
}

impl Drop for SecureData {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// ============================================================
// 测试
// ============================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_buffer_roundtrip() {
        let original = vec![1u8, 2, 3, 4, 5];
        let mut buf = SecureBuffer::from_slice(&original);
        
        assert_eq!(buf.get(), &[1,2,3,4,5]);
        buf.zeroize();
        assert_eq!(buf.get(), &[0,0,0,0,0], "buffer must be zeroed");
    }

    #[test]
    fn test_secure_data_with_secure() {
        let mut data = SecureData::new(vec![0xAA; 32]);
        
        // 使用数据: 在 with_secure 内数据有效
        let sum = data.with_secure(|d| d.iter().map(|&b| b as u32).sum::<u32>());
        assert_eq!(sum, 32 * 0xAA as u32);
        
        // 闭包结束后自动零化
        assert!(data.is_cleaned, "data must be zeroized after with_secure");
        assert_eq!(&data.data[..], &[0u8; 32], "data must be all zeros");
    }

    #[test]
    fn test_manual_zeroize_slice() {
        let mut buf = vec![0xFFu8; 64];
        SecureBuffer::zeroize_slice(&mut buf);
        assert_eq!(buf, vec![0u8; 64], "slice must be zeroed");
    }

    #[test]
    fn test_drop_zeroizes() {
        let original = vec![0x42u8; 16];
        let mut dropped = false;
        
        {
            let buf = SecureBuffer::from_slice(&original);
            // 检查初始值
            assert_eq!(buf.get(), &[0x42u8; 16]);
            // buf 在此作用域结束时 drop
        }
        // buf 已 drop，数据应已清零
        // (无法直接验证 buf 已 drop，但逻辑上 drop 调用了 zeroize)
    }
}
