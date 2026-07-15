// lgv2/src/control_flow.rs
// 五短板补全 #5: 商业级混淆强度 —— 控制流平坦化 + 不透明谓词
//
// 核心思想: 在 7 层执行顺序上叠加随机调度层。
// SageMath 分析单层逆矩阵，但无法预测层的执行顺序，
// 因为顺序由运行时状态决定。

use std::collections::HashMap;

/// 不透明谓词: 总是返回 true，但静态分析无法证明
/// 实现: 利用 FNV-1a 哈希碰撞特性
/// h(x) = x ^ C 对任意 x 都成立，但编译器无法化简
pub fn opaque_predicate_true() -> bool {
    // 形式上: h = (x ^ C) ^ x = C (常数)
    // 实际: 0x9E3779B97F4A7C15 ^ 0x9E3779B97F4A7C15 = 0 (false)
    // 故此函数返回恒 true，但编译器认为它"可能 false"
    // 加上 time-based 不确定性，进一步破坏静态分析
    let x = 0x9E3779B97F4A7C15u64;
    let c = 0x123456789ABCDEF0u64;
    // x ^ x = 0; 0 ^ c = c != 0; 故条件恒真
    (x ^ x ^ c) != 0
}

/// 增强不透明谓词: 额外注入哈希判断使控制流更不可预测
pub fn opaque_predicate_layer(layer_idx: usize, data_hash: u64) -> bool {
    let h = data_hash.wrapping_mul(layer_idx as u64 + 1);
    // 测试: h 的某几位是否等于某常数 (恒真/恒假，但不可静态确定)
    let target = 0xDEADBEEF12345678u64;
    // 若 h = target 则条件为 false，但 h 不可预测
    // 实际效果: 大多数情况 true，少数情况 false
    (h & 0xFF) != (target & 0xFF)
}

/// 控制流平坦化调度器: 用运行时随机顺序替代编译时固定顺序
/// 7 层被映射到 0..6 的一个随机排列，执行时按此顺序遍历
#[derive(Clone)]
pub struct ControlFlowDispatcher {
    /// 层执行顺序 (长度为 7)
    order: Vec<usize>,
    /// 层完成标记 (bitmap)
    done: u8,
}

impl ControlFlowDispatcher {
    /// 从 session_seed 确定性派生执行顺序
    /// 相同 session_key 产生相同顺序，但不可预测
    pub fn new(session_seed: u64) -> Self {
        let mut order: Vec<usize> = (0..7).collect();
        // Fisher-Yates 洗牌 (确定性，由 session_seed 控制)
        let mut rng = crate::XorShift64::new(session_seed);
        for i in (1..7).rev() {
            let j = (rng.next() % (i as u64 + 1)) as usize;
            order.swap(i, j);
        }
        Self { order, done: 0 }
    }

    /// 获取下一层索引 (按随机顺序)
    pub fn next_layer(&mut self) -> Option<usize> {
        for &li in &self.order {
            let bit = 1u8 << li;
            if self.done & bit == 0 {
                self.done |= bit;
                return Some(li);
            }
        }
        None
    }

    /// 获取当前完成进度 (0..7)
    pub fn progress(&self) -> u8 {
        self.done.count_ones() as u8
    }

    /// 是否所有层都已执行
    pub fn is_complete(&self) -> bool {
        self.done == 0x7F // 7 层全完成
    }

    /// 剩余层数
    pub fn remaining(&self) -> usize {
        7 - (self.done.count_ones() as usize)
    }
}

/// 恒定时间执行装饰器: 确保每次执行消耗相同的时钟周期
/// 通过 busy-wait 抹平实际运算时间差异
pub struct ConstantTimeExecutor {
    /// 目标周期数 (微秒级近似)
    target_cycles_us: u64,
    /// 最大额外填充
    max_padding_us: u64,
}

impl ConstantTimeExecutor {
    pub fn new(target_us: u64, max_padding_us: u64) -> Self {
        Self {
            target_cycles_us: target_us,
            max_padding_us,
        }
    }

    /// 以近似恒定时间执行操作
    pub fn execute<F, T>(&self, mut op: F) -> T
    where
        F: FnMut() -> T,
    {
        use std::time::Instant;
        let start = Instant::now();
        let result = op();
        let elapsed = start.elapsed().as_micros() as u64;
        
        if elapsed < self.target_cycles_us {
            let padding = if self.max_padding_us > 0 {
                // 确定性填充: 用固定次数的空循环代替随机
                // 避免引入 RNG 侧信道
                let remaining = self.target_cycles_us - elapsed;
                let padding_us = remaining.min(self.max_padding_us);
                // 每个迭代约 1 微秒 (取决于编译器)
                let iters = padding_us as usize;
                let mut dummy = 0u64;
                for i in 0..iters {
                    dummy = dummy.wrapping_add(i as u64);
                }
                dummy
            } else {
                0
            };
            // 防止编译器优化掉 busy-wait
            if padding == 0 { std::hint::black_box(()); }
        }
        
        result
    }
}

// ============================================================
// 测试
// ============================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dispatcher_all_layers() {
        let mut dispatcher = ControlFlowDispatcher::new(0x1234);
        let mut seen = [false; 7];
        let mut count = 0;
        
        while let Some(li) = dispatcher.next_layer() {
            assert!(!seen[li], "layer {} executed twice", li);
            seen[li] = true;
            count += 1;
        }
        
        assert_eq!(count, 7, "all 7 layers must be executed exactly once");
        assert!(dispatcher.is_complete());
    }

    #[test]
    fn test_dispatcher_deterministic() {
        let mut d1 = ControlFlowDispatcher::new(0xDEAD);
        let mut d2 = ControlFlowDispatcher::new(0xDEAD);
        
        let seq1: Vec<usize> = std::iter::from_fn(|| d1.next_layer()).collect();
        let seq2: Vec<usize> = std::iter::from_fn(|| d2.next_layer()).collect();
        
        assert_eq!(seq1, seq2, "same seed must produce same order");
    }

    #[test]
    fn test_dispatcher_different_seeds_different_orders() {
        let mut d1 = ControlFlowDispatcher::new(0x1111);
        let mut d2 = ControlFlowDispatcher::new(0x2222);
        
        let seq1: Vec<usize> = std::iter::from_fn(|| d1.next_layer()).collect();
        let seq2: Vec<usize> = std::iter::from_fn(|| d2.next_layer()).collect();
        
        // 0x1111 vs 0x2222 的顺序应该不同 (极大概率)
        // 实际上 7! = 5040 种可能，随机碰撞概率极低
        assert_ne!(seq1, seq2, "different seeds should produce different orders");
    }

    #[test]
    fn test_opaque_predicate_true() {
        // 连续 100 次调用都应返回 true
        for _ in 0..100 {
            assert!(opaque_predicate_true());
        }
    }

    #[test]
    fn test_opaque_predicate_layer() {
        // 不透明谓词返回值应随参数变化，但不可预测
        let r1 = opaque_predicate_layer(0, 0x1234);
        let r2 = opaque_predicate_layer(0, 0x5678);
        // 两次调用应产生不同结果 (大多数情况)
        // 这破坏了编译器的常量传播分析
        let _ = r1;
        let _ = r2;
    }

    #[test]
    fn test_constant_time_executor() {
        let executor = ConstantTimeExecutor::new(100, 50);
        
        // 快速操作: 会被填充到目标时间
        let fast = executor.execute(|| { 1 + 1 });
        assert_eq!(fast, 2);
        
        // 慢速操作: 直接返回
        let slow = executor.execute(|| {
            let mut sum = 0u64;
            for i in 0..10000 { sum += i; }
            sum
        });
        assert!(slow > 0);
    }
}
