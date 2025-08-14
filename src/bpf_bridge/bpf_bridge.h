#ifndef MICROBPF_BRIDGE_H
#define MICROBPF_BRIDGE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Verifies and executes an eBPF program.
 *
 * This function is the C entry point into the Rust-based eBPF engine.
 * It first runs the bytecode through a hardened verifier. If verification
 * passes, it executes the program using an interpreter.
 *
 * @param bytecode Pointer to the eBPF bytecode.
 * @param bytecode_len Length of the bytecode array.
 * @param mem Pointer to the memory context for the program (R1).
 * @param mem_len Length of the memory context.
 * @param result Output parameter to store the program's 64-bit result (from R0).
 *
 * @return 0 on success, ULLONG_MAX on failure (verification or execution error).
 */
uint64_t bpf_run_program(
    const uint8_t* bytecode,
    size_t bytecode_len,
    void* mem,
    size_t mem_len,
    uint64_t* result
);

#ifdef __cplusplus
}
#endif

#endif // MICROBPF_BRIDGE_H