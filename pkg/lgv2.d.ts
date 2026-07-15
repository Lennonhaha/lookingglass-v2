/* tslint:disable */
/* eslint-disable */

/**
 * 密码学绑定: 将混淆输出与 ML-KEM 共享密钥绑定
 * kem_ss: 32 字节 ML-KEM 共享密钥
 * 返回: 混淆结果 XOR Keccak-256(binding_label || MLKEM_SS)
 */
export function lgv2_bind_kem(data: Uint8Array, kem_ss: Uint8Array): Uint8Array;

export function lgv2_confuse(data: Uint8Array, seed: bigint): Uint8Array;

/**
 * 增强混淆: 固定路径 (SUB+Linear) + session 差异化 + 安全零化
 * seed ^ session_key 派生会话特定种子，确保不同会话产生不同输出
 */
export function lgv2_confuse_ex(data: Uint8Array, seed: bigint, session_key: bigint): Uint8Array;

/**
 * 端到端安全混淆: 动态路径 + ML-KEM 绑定
 * combines confuse_ex + bind_kem in one call
 */
export function lgv2_confuse_full(data: Uint8Array, seed: bigint, session_key: bigint, kem_ss: Uint8Array): Uint8Array;

export function lgv2_deconfuse(data: Uint8Array, seed: bigint): Uint8Array;

/**
 * 增强解混淆: 固定路径 + session 差异化
 * session_key 必须与混淆时一致 (same combined_seed = seed ^ session_key)
 */
export function lgv2_deconfuse_ex(data: Uint8Array, seed: bigint, session_key: bigint): Uint8Array;

/**
 * 端到端安全解绑: ML-KEM 解绑 + 动态路径解混淆
 */
export function lgv2_deconfuse_full(data: Uint8Array, seed: bigint, session_key: bigint, kem_ss: Uint8Array): Uint8Array;

/**
 * 密码学解绑: 使用相同 ML-KEM 共享密钥解除绑定
 */
export function lgv2_unbind_kem(data: Uint8Array, kem_ss: Uint8Array): Uint8Array;

/**
 * 获取库版本信息
 */
export function lgv2_version(): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly lgv2_bind_kem: (a: number, b: number, c: number, d: number) => [number, number];
    readonly lgv2_confuse: (a: number, b: number, c: bigint) => [number, number];
    readonly lgv2_confuse_ex: (a: number, b: number, c: bigint, d: bigint) => [number, number];
    readonly lgv2_confuse_full: (a: number, b: number, c: bigint, d: bigint, e: number, f: number) => [number, number];
    readonly lgv2_deconfuse: (a: number, b: number, c: bigint) => [number, number];
    readonly lgv2_deconfuse_ex: (a: number, b: number, c: bigint, d: bigint) => [number, number];
    readonly lgv2_deconfuse_full: (a: number, b: number, c: bigint, d: bigint, e: number, f: number) => [number, number];
    readonly lgv2_version: () => [number, number];
    readonly lgv2_unbind_kem: (a: number, b: number, c: number, d: number) => [number, number];
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
