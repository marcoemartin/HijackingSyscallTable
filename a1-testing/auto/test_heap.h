/* Copyright 2014 Peter Goodman, all rights reserved. */

#ifndef LAB1_TEST_HEAP_H_
#define LAB1_TEST_HEAP_H_

#include <sys/types.h>
#include <stdint.h>
#include <pthread.h>

struct Histogram {
  // Sume of the `count` buckets. This is the number of entries in the
  // histogram.
  int total_count;

  // Sum of the *exact* values added to the histogram (can be under-estimated
  // using the `count` buckes).
  size_t sum;

  // Counts the number of inputs for each power of two.
  int count[64];
};

// Defines the heap used to test CSC 369 lab 1, phase 1 and phase 2.
struct Heap {

  // Heap size proportions: num_bytes <= usable_num_bytes < total_num_bytes.
  size_t num_bytes;
  size_t usable_num_bytes;
  size_t total_num_bytes;

  // Heap memory is arranged as:
  //
  //  redzone_base               <--- sbrk --->              redzone_limit
  //      |----------|-----------------------------------|----------|
  //                base                ^               limit
  //
  // The pages in the range [redzone_base, base) and [limit, redzone_limit)
  // are protected against reads and writes. This is to detect overflows of
  // the heap itself.
  char *redzone_base;
  char *base;
  char *sbrk;
  char *limit;
  char *redzone_limit;

  // Random seed used for fuzzing.
  unsigned rng_seed;

  // Enforces re-entrancy and also detects non-reentrant uses of `sbrk`.
  pthread_mutex_t sbrk_mutex;

  struct {
    // Number of calls to `malloc`.
    struct Histogram malloc_calls;

    // Number of calls to `sbrk`, where the break pointer is incremented.
    struct Histogram sbrk_calls_positive;
    int num_failed_sbrk_calls_positive;
    int num_eagain_sbrk_calls;

    // Number of calls to `sbrk`, where the break pointer is decremented.
    struct Histogram sbrk_calls_negative;

    // Number of calls to `sbrk(0)`.
    int num_sbrk_calls_zero;

    // Total amount of allocated memory vs. total "live" memory. This is
    // based on `malloc` and `free`.
    volatile size_t total_allocated_memory;
    volatile size_t allocated_memory;
  } stats;

  struct HeapOptions {
    // By default, all memory in the range [base, limit) is poisoned with this
    // value. This allows us to detect some types of write overflows at a byte-
    // granularity. If we decrement the `sbrk` pointer, then we'll re-poison
    // the memory after the `sbrk`.
    //
    // If this value is `0` then no poisoning is done.
    int uninit_poison_val;

    // Value to newly `sbrk`d memory with. This distinguished requested memory
    // from unrequested memory. The idea being that across two runs of a
    // program, we should be able to accurately distinguish the memory
    // overhead of meta-data, alignment/padding, etc. by looking for bytes that
    // aren't the `init_posion_val` and aren't the `uinint_poison_val`.
    //
    // If this value is `0` then no poisoning is done.
    int init_poison_val;

    // Value to poison `malloc`d memory with.
    //
    // If this value is `0` then no poisoning is done.
    int malloc_poison_val;

    // Value to poison `free`d memory with.
    //
    // If this value is `0` then no poisoning is done.
    int free_poison_val;

    // What is the minimum amount by which `sbrk` should increment a value?
    //
    // If this value is `0`, then the exact amount of memory requested will
    // be given to the user. If this value is `16`, then memory given to the
    // user in increments of `16`.
    //
    // If this value is non-zero, then `max_sbrk_increment_fuzz` should be `0`.
    int min_sbrk_increment;

    // `sbrk` doesn't guarantee any useful alignment of the pointer it returns.
    // We'll take this as a hint that we can add an arbitrary (positive)
    // displacement to the requested size.
    //
    // If this value is `0` then no fuzzing is done.
    int max_sbrk_increment_fuzz;

    // Should sbrk be treated as being reentrant?
    int use_reentrant_sbrk;

    // Should we fuzz on `EAGAIN`? This would allow us to temporarily reject
    // a request for memory, under the expectation that we can satisfy it
    // later.
    //
    // If the value is `0` then that says never fail and set `errno` to
    // `EAGAIN`. However, if the number is `10`, then that says `fuzz` one out
    // of every `10` calls to `sbrk`.
    //
    // Note: This type of fuzzing only applies to `sbrk` invocations with a
    //       positive amount of requested memory.
    int fuzz_eagain;

  } options;

  struct {
    // Does the code write any values beyond the `sbrk` pointer?
    int bug_write_beyond_sbrk;

    // Does the code try to deallocate too much memory? This happens when
    // a negative input to `sbrk` frees more than the entire heap.
    int bug_releases_too_much_memory;

    // Does the code assume that `sbrk` is reentrant? If so, this tells us if
    // we caught an instance where this assumption was violated due to two
    // concurrent calls of `sbrk`.
    //
    // Note: This is only meaningful if `options.use_reentrant_sbrk = 0`.
    volatile int bug_non_reentrant_sbrk;

    // Records the number of failed calls to `mymalloc`.
    volatile int num_failed_mallocs;

    // Records the number of failed calls to `myfree` where the address to be
    // freed is `NULL`.
    volatile int num_failed_frees;

    // Records the number of failed calls to `myfree` where the address
    // being freed is NULL.
    volatile int num_failed_frees_null;
  } traps;
};

typedef void (ConfigFunc)(struct HeapOptions *);

// (Re-)Initialize the heap for a given heap size.
struct Heap *AllocHeap(size_t num_bytes, ConfigFunc *config);

// Destroys the heap.
void FreeHeap(struct Heap *heap);

// System `sbrk` for use by `mymalloc` and `myfree`.
void *ShiftBreak(struct Heap *heap, intptr_t num_bytes);

// Tell the heap that a malloc has been done. This should be executed
// *after* `mymalloc` is invoked.
void *Malloc(struct Heap *heap, size_t size);

// Tell the heap that a free is *about* to be done. This should be executed
// *`before* `myfree` is invoked.
enum FreeStatus {
  FREE_SUCCESS,
  FREE_FAIL_NULLPTR,
  FREE_UNKNOWN_FAIL
};

enum FreeStatus Free(struct Heap *heap, void *addr, size_t size);

// Allocate some memory, but expect to fail.
void *MallocFail(struct Heap *heap, size_t size);

// Free memory, but expect to fail.
void FreeFail(struct Heap *heap, void *addr, size_t size);

// Returns `1` if `addr` is in the heap, otherwise `0`.
int IsHeapAddress(struct Heap *heap, void *addr);

// Produce a report about the heap.
void Report(struct Heap *heap);

#endif  // LAB1_TEST_HEAP_H_
