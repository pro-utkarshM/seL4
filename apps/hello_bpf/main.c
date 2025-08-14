#include <stdio.h>
#include <stdint.h>
#include <string.h>
// #include "bpf_bridge.h" // Include our new bridge header
#include "../src/bpf_bridge/bpf_bridge.h" // Update path if the header is in the parent directory

// A simple, valid eBPF program that calculates 15.
// r0 = 5
// r0 += 10
// exit
const uint8_t hello_bpf_program[] = {
    0xb7, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, // mov64 r0, 5
    0x07, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, // add64 r0, 10
    0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
};

// An invalid eBPF program with a backward jump (loop).
const uint8_t invalid_loop_program[] = {
    0x05, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, // ja -1
    0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
};

int main(void) {
    printf("--- MicroBPF-Kernel Phase 1 Test Application ---\n");

    uint64_t result = 0;
    uint64_t status = 0;
    char memory_context[16] = "Test Context";

    // --- Test 1: Execute the valid program ---
    printf("Executing valid 'hello_bpf_program'...\n");
    status = bpf_run_program(
        hello_bpf_program,
        sizeof(hello_bpf_program),
        memory_context,
        sizeof(memory_context),
        &result
    );

    if (status == 0) {
        printf("Execution successful.\n");
        printf("Result from eBPF program (R0): %llu\n", result);
        if (result == 15) {
            printf("SUCCESS: Result is correct.\n");
        } else {
            printf("FAILURE: Result is incorrect.\n");
        }
    } else {
        printf("FAILURE: Execution of valid program failed.\n");
    }

    printf("\n");

    // --- Test 2: Attempt to execute the invalid program ---
    printf("Executing 'invalid_loop_program' (expected to fail verification)...\n");
    status = bpf_run_program(
        invalid_loop_program,
        sizeof(invalid_loop_program),
        memory_context,
        sizeof(memory_context),
        &result
    );

    if (status != 0) {
        printf("SUCCESS: Engine correctly rejected the invalid program.\n");
    } else {
        printf("FAILURE: Engine executed an invalid program that should have been rejected.\n");
    }

    printf("\n--- Test complete. ---\n");

    return 0;
}