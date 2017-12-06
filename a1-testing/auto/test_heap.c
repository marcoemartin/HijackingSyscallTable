/* Copyright 2014 Peter Goodman, all rights reserved. */

#undef calloc
#undef free
#undef mmap

#include "test_clock.h"
#include "test_heap.h"

#include <assert.h>
#include <errno.h>
#include <math.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

enum {
  PAGE_SIZE = 4096,
  MAX_OVEFLOW_CHECK = 1024
};

#define ROUND_UP(x, amt) ((((x) + (amt - 1)) / amt) * amt)

extern void *mymalloc(unsigned int size);
extern int myfree(void *ptr);

static void UpdateHistogram(struct Histogram *hist, size_t val) {
  size_t max_bit = 63 - __builtin_clzll(val);
  assert(max_bit < 64);
  hist->count[max_bit] += 1;
  ++hist->total_count;
  hist->sum += val;
}

// Print out a histogram.
static void DisplayHistogram(struct Histogram *hist, const char *desc) {
  int i = 0;
  int max_count = 0;
  int max_bin = 0;
  float max_stars = 30;
  float stars_per_count;

  for (i = 0; i < 32; ++i) {
    if (hist->count[i]) {
      max_bin = i + 1;
    }
  }

  if (!max_bin) return;  // Nothing to show for this histogram.

  for (i = 0; i < max_bin; ++i) {
    if (hist->count[i] > max_count) {
      max_count = hist->count[i];
    }
  }

  stars_per_count = max_count / max_stars;

  printf("%s\n", desc);
  printf("Sum of all sizes: %lu\n", hist->sum);
  printf("Number of calls: %d\n", hist->total_count);
  for (i = 0; i < max_bin; ++i) {
    int num_stars = (int) (((float) hist->count[i]) / stars_per_count);
    if (!num_stars && hist->count[i]) num_stars = 1;
    printf("%2d | ", i);
    for (; num_stars-- > 0; ) {
      printf("*");
    }
    printf("\n");
  }
  printf("\n");
}

// Try to detect an overflow of the `sbrk` pointer.
static int DetectOverflow(char *base, char *limit, int val_) {
  ptrdiff_t i = 0;
  ptrdiff_t diff = limit - base;
  const char val = (char) val_;
  if (diff > MAX_OVEFLOW_CHECK) diff = MAX_OVEFLOW_CHECK;
  for (; i < diff; ++i) {
    if (val != base[i]) {
      return 1;
    }
  }
  return 0;
}

// (Re-)Initialize the heap for a given heap size.
struct Heap *AllocHeap(size_t num_bytes, ConfigFunc *config) {
  struct Heap *heap = calloc(1UL, sizeof(struct Heap));
  pthread_mutex_init(&(heap->sbrk_mutex), NULL);

  heap->num_bytes = num_bytes;
  heap->usable_num_bytes = ROUND_UP(num_bytes, PAGE_SIZE);
  heap->total_num_bytes = PAGE_SIZE + heap->usable_num_bytes + PAGE_SIZE;

  // Set up the main heap.
  heap->redzone_base = (char *) mmap(NULL, heap->total_num_bytes,
                                     PROT_READ | PROT_WRITE,
                                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  heap->redzone_limit = heap->redzone_base + heap->total_num_bytes;
  heap->base = heap->redzone_base + PAGE_SIZE;
  heap->sbrk = heap->base;
  heap->limit = heap->redzone_limit - PAGE_SIZE;

  // Protect the redzones.
  mprotect(heap->redzone_base, PAGE_SIZE, PROT_NONE);
  mprotect(heap->limit, PAGE_SIZE, PROT_NONE);

  // Set up random seed for fuzzing.
  heap->rng_seed = 0xDEADBEEFU;
  srand(heap->rng_seed);

  config(&(heap->options));

  // Poison the heap.
  if (heap->options.uninit_poison_val) {
    memset(heap->base, heap->options.uninit_poison_val, heap->usable_num_bytes);
  }

  return heap;
}

// Destroys the heap.
void FreeHeap(struct Heap *heap) {
  pthread_mutex_destroy(&(heap->sbrk_mutex));
  munmap(heap->redzone_base, heap->total_num_bytes);
  free(heap);
}

// System `sbrk` for use by `mymalloc` and `myfree`.
//
// TODO(pag): Currently not checking for integer overflows of `num_bytes` with
//            `heap->sbrk`.
void *ShiftBreak(struct Heap *heap, const intptr_t num_bytes_) {
  intptr_t num_bytes = num_bytes_;
  void *retval = (void *) -1;

  // Try to detect non-reentrant uses of `sbrk`, but either way, get mutual
  // exclusion over `heap`.
  if (0 != pthread_mutex_trylock(&(heap->sbrk_mutex))) {
    if (!heap->options.use_reentrant_sbrk &&
        !heap->traps.bug_non_reentrant_sbrk) {
      heap->traps.bug_non_reentrant_sbrk = 1;
    }
    pthread_mutex_lock(&(heap->sbrk_mutex));
  }

  // Allocating.
  if (num_bytes > 0) {
    UpdateHistogram(&(heap->stats.sbrk_calls_positive), (size_t) num_bytes);

    // Look for overflow bugs.
    if (heap->options.uninit_poison_val &&
        !heap->traps.bug_write_beyond_sbrk &&
        DetectOverflow(heap->sbrk, heap->limit,
                       heap->options.uninit_poison_val)) {
      heap->traps.bug_write_beyond_sbrk = 1;
    }

    // Basic check.
    if ((heap->sbrk + num_bytes) >= heap->limit) {
      errno = ENOMEM;
      ++heap->stats.num_failed_sbrk_calls_positive;
      goto out;
    }

    // Should we align all `sbrk` pointers?
    if (heap->options.min_sbrk_increment) {
      num_bytes = ROUND_UP(num_bytes, heap->options.min_sbrk_increment);

    // Should we fuzz on alignment? If so, add some extra amount of memory
    // to their request.
    } else if (heap->options.max_sbrk_increment_fuzz) {
      num_bytes += rand() % heap->options.max_sbrk_increment_fuzz;
    }

    // Re-check for enough space.
    if ((heap->sbrk + num_bytes) >= heap->limit) {
      errno = ENOMEM;
      ++heap->stats.num_failed_sbrk_calls_positive;
      goto out;
    }

    // Should we fuzz on EAGAIN?
    if (heap->options.fuzz_eagain &&
        !(heap->stats.sbrk_calls_positive.total_count %
          heap->options.fuzz_eagain)) {
      errno = EAGAIN;
      goto out;
    }

    // Success!
    retval = heap->sbrk;
    heap->sbrk += num_bytes;

    // Poison the requested memory, but *not* the extra size added in.
    if (heap->options.init_poison_val) {
      memset(retval, heap->options.init_poison_val, (size_t) num_bytes_);
    }

  // Freeing.
  } else if (num_bytes < 0) {
    const ptrdiff_t diff = heap->sbrk - heap->base;

    UpdateHistogram(&(heap->stats.sbrk_calls_negative),
                    (size_t) -num_bytes);

    if (num_bytes > diff) {
      heap->traps.bug_releases_too_much_memory = 1;
      errno = ENOMEM;
      goto out;
    }

    retval = heap->sbrk;
    heap->sbrk += num_bytes;  // Decrements the `sbrk` pointer.

    // Re-poison the memory, if necessary.
    if (heap->options.uninit_poison_val &&
        !heap->traps.bug_write_beyond_sbrk) {
      memset(heap->sbrk, heap->options.uninit_poison_val, (size_t) num_bytes);
    }

  // Querying.
  } else {
    ++heap->stats.num_sbrk_calls_zero;
    retval = heap->sbrk;
  }

out:
  pthread_mutex_unlock(&(heap->sbrk_mutex));

  return retval;
}

// Tell the heap that a malloc has been done.
void *Malloc(struct Heap *heap, size_t size) {
  void *addr = NULL;

  StartClock();
  addr = mymalloc(size);
  EndClock();

  UpdateHistogram(&(heap->stats.malloc_calls), size);

  if (IsHeapAddress(heap, addr)) {
    if (heap->options.malloc_poison_val) {
      memset(addr, heap->options.malloc_poison_val, size);
    }
    __sync_fetch_and_add(&(heap->stats.total_allocated_memory), size);
    __sync_fetch_and_add(&(heap->stats.allocated_memory), size);
  } else {
    __sync_fetch_and_add(&(heap->traps.num_failed_mallocs), 1);
  }

  return addr;
}

// Tell the heap that a free is *about* to be done. This should be executed
// *before* `myfree` is invoked.
enum FreeStatus Free(struct Heap *heap, void *addr, size_t size) {
  int ret = 0;
  if (IsHeapAddress(heap, addr)) {
    if (heap->options.free_poison_val) {
      memset(addr, heap->options.free_poison_val, size);
    }
    __sync_fetch_and_sub(&(heap->stats.allocated_memory), size);
  }

  StartClock();
  ret = myfree(addr);
  EndClock();

  if (ret) {
    if (addr) {
      __sync_fetch_and_add(&(heap->traps.num_failed_frees), 1);
      return FREE_UNKNOWN_FAIL;
    } else {
      __sync_fetch_and_add(&(heap->traps.num_failed_frees_null), 1);
      return FREE_FAIL_NULLPTR;
    }
  }
  return FREE_SUCCESS;
}

// Allocate some memory, but expect to fail.
void *MallocFail(struct Heap *heap, size_t size) {
  void *addr = Malloc(heap, size);
  if (!addr) {
    __sync_fetch_and_sub(&(heap->traps.num_failed_mallocs), 1);
  } else {
    printf("BAD: Malloc of size %lu unexpectedly succeeded.\n",
            size);
  }
  return addr;
}

// Free memory, but expect to fail.
void FreeFail(struct Heap *heap, void *addr, size_t size) {
  switch (Free(heap, addr, size)) {
    case FREE_SUCCESS:
      printf("BAD: Free of size %lu unexpectedly succeeded.\n",
              size);
      return;
    case FREE_FAIL_NULLPTR:
      printf("GOOD: Call to `myfree(NULL)` failed in an expected "
              "way.\n");
      __sync_fetch_and_sub(&(heap->traps.num_failed_frees_null), 1);
      return;
    case FREE_UNKNOWN_FAIL:
      printf("GOOD: Call to `myfree` failed in an expected way.\n");
      __sync_fetch_and_sub(&(heap->traps.num_failed_frees), 1);
      return;
  }
}

// Returns `1` if `addr` is in the heap, otherwise `0`.
int IsHeapAddress(struct Heap *heap, void *addr_) {
  const char *addr = (const char *) addr_;
  return heap->base <= addr && addr < heap->limit;
}

static double CountBytes(const char *base, const char *limit, int search) {
  int num_found = 0;
  for (; base < limit; ++base) {
    if (((char) search) == *base) {
      ++num_found;
    }
  }
  return (double) num_found;
}



static void FineGrainedUtilization(struct Heap *heap) {
  double sbrk_size = (double) (heap->sbrk - heap->base);
  double num_malloc_bytes = CountBytes(heap->base, heap->sbrk,
                                       heap->options.malloc_poison_val);
  double num_unused_free_bytes = CountBytes(heap->base, heap->sbrk,
                                            heap->options.free_poison_val);
  double num_sbrk_bytes = CountBytes(heap->base, heap->sbrk,
                                     heap->options.init_poison_val);

  printf("Unused free space in system break: %d%%\n",
         (int) rint(100.0 * (num_unused_free_bytes / sbrk_size)));

  printf("Padding overhead / unused space in system break: %d%%\n",
         (int) rint(100.0 * (num_sbrk_bytes / sbrk_size)));

  printf("Meta-data overhead in system break: %d%%\n",
         (int) rint(((sbrk_size - num_sbrk_bytes - num_malloc_bytes -
          num_unused_free_bytes) / sbrk_size) * 100.0));
}

// Produce a report about the heap.
void Report(struct Heap *heap) {
  double a, b;
  ptrdiff_t sbrk_size = heap->sbrk - heap->base;
  if (heap->traps.bug_write_beyond_sbrk) {
    printf("BAD: Detected an overflow of the system break pointer.\n");
  }

  if (heap->traps.bug_releases_too_much_memory) {
    printf("BAD: Detected a too-large negative input to `sbrk` that would "
           "free more than the entire heap.\n");
  }

  if (heap->traps.bug_non_reentrant_sbrk) {
    printf("BAD: Detected non-reentrant uses of `sbrk`. Calls to `sbrk` "
           "should be guarded by a mutex.");
  }

  if (heap->traps.num_failed_mallocs) {
    printf("BAD: %d calls to `mymalloc` unexpectedly failed.\n",
           heap->traps.num_failed_mallocs);
  }

  if (heap->traps.num_failed_frees) {
    printf("BAD: %d calls to `myfree` unexpectedly failed.\n",
           heap->traps.num_failed_frees);
  }

  DisplayHistogram(&(heap->stats.malloc_calls),
                   "Calls to `mymalloc` (log2 scale):");
  DisplayHistogram(&(heap->stats.sbrk_calls_positive),
                   "Calls to `sbrk` with positive break amounts (log2 scale):");
  DisplayHistogram(&(heap->stats.sbrk_calls_negative),
                   "Calls to `sbrk` with negative break amounts (log2 scale):");

  printf("Number of calls to `sbrk(0)`: %d\n",
         heap->stats.num_sbrk_calls_zero);

  printf("Sum of `mymalloc`s + `myfree`s: %lu bytes (%ld pages)\n",
         heap->stats.allocated_memory,
         heap->stats.allocated_memory / PAGE_SIZE);

  printf ("Size of the system break: %ld bytes (%ld pages).\n",
          sbrk_size, ROUND_UP((size_t)sbrk_size, PAGE_SIZE) / PAGE_SIZE);

  printf("Sum of `mymalloc`s: %lu bytes (%lu pages).\n",
         heap->stats.total_allocated_memory,
         heap->stats.total_allocated_memory / PAGE_SIZE);

  printf ("Maximum size of the system break: %lu bytes (%ld pages).\n",
          heap->usable_num_bytes, heap->usable_num_bytes / PAGE_SIZE);

  a = (double) heap->stats.allocated_memory;
  b = (double) sbrk_size;
  printf("Watermark memory utilization: %d%%\n", (int) rint((a / b) * 100.0));

  if (heap->options.init_poison_val) {
    FineGrainedUtilization(heap);
  }

  if (heap->stats.num_failed_sbrk_calls_positive) {
    printf("Number of failed calls to `sbrk`: %d\n",
           heap->stats.num_failed_sbrk_calls_positive);
  }

  if (heap->stats.num_eagain_sbrk_calls) {
    printf("Number of calls to `sbrk` that (purposefully) return EAGAIN: %d\n",
           heap->stats.num_eagain_sbrk_calls);
  }
}
