#ifndef HSS_CONFIG_H
#define HSS_CONFIG_H

#include <stdint.h>

// ==========================================
// Dimensions (Configurable for RLWE)
// ==========================================

// N is the degree of the polynomial ring R_q = Z_q[x] / (x^N + 1)
// Standard values: 128, 256, 512, 1024
#ifndef HSS_N
#define HSS_N 128
#endif

// In RLWE-based HSS for inner product, the expansion factor K is no longer needed.
// We operate directly in the ring of degree N.
#define HSS_D HSS_N

// ==========================================
// Moduli & Parameters (128-bit Arithmetic)
// ==========================================

// 使用 128 位整数以支持更大的模数
typedef unsigned __int128 hss_int_t;

// Q = 2^90 (留下一些空间防止加法溢出 128 位)
#define HSS_LOG2_Q 90
#define HSS_Q ((hss_int_t)1 << HSS_LOG2_Q)
#define HSS_Q_MASK (HSS_Q - 1)

// P = 2^60 (足够容纳 N=128, input=2^26 左右的内积)
// Max inner prod approx: 128 * (2^26)^2 = 2^59.
#define HSS_LOG2_P 60
#define HSS_P ((hss_int_t)1 << HSS_LOG2_P)
#define HSS_P_MASK (HSS_P - 1)

// Scaling factor Delta = Q / P = 2^30
#define HSS_DELTA (HSS_Q / HSS_P)

// Scaling factor for Face Vectors (Float -> Int)
// 2^16 = 65536.0 used for converting input floats to integers
#ifndef HSS_SCALE
#define HSS_SCALE 65536.0
#endif

// Noise Parameters
#define HSS_NOISE_ETA 2

#endif