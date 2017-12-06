/* Copyright 2014 Peter Goodman, all rights reserved. */

#include "test_clock.h"
#include "test_trace.h"

#include <assert.h>
#include <stdio.h>

static int next_idx[MAX_NUM_THREADS] = {0};
static int max_thread_id = -1;
static struct TraceEntry traces[MAX_NUM_THREADS][MAX_NUM_EVENTS];

// Parse a trace line.
void ParseTraceLine(const char *line, int line_num) {
  int thread = 0;
  int malloc_size = 0;
  int id = 0;
  int skew = 0;
  int entry_id = 0;
  int expect_error = 0;
  struct TraceEntry *entry = NULL;

  if (sscanf(line, "m %d %d %d", &thread, &id, &malloc_size)) {
    entry_id = next_idx[thread]++;
    assert(id == entry_id);

    entry = &(traces[thread][entry_id]);
    entry->action = ACTION_MALLOC;
    entry->malloc.malloc_size = malloc_size;
    entry->malloc.address = NULL;

  } else if (sscanf(line, "fn %d", &thread)) {
    entry_id = next_idx[thread]++;
    entry = &(traces[thread][entry_id]);
    entry->action = ACTION_FREE_NULL;

  } else if (sscanf(line, "fs %d %d %d", &thread, &id, &skew)) {
    expect_error = 0 != skew;
    goto init_free;

  } else if (sscanf(line, "fe %d %d", &thread, &id)) {
    expect_error = 1;
    goto init_free;

  } else if (sscanf(line, "f %d %d", &thread, &id)) {
  init_free:
    assert(0 <= thread && thread < MAX_NUM_THREADS);
    entry_id = next_idx[thread]++;
    assert(0 <= id && id < entry_id);
    assert(ACTION_MALLOC == traces[thread][id].action);

    entry = &(traces[thread][entry_id]);
    entry->action = ACTION_FREE;
    entry->free.addr_skew = skew;
    entry->free.expect_error = expect_error;
    entry->free.malloc_index = id;
  } else {
    return;
  }

  entry->line = line_num;

  if (thread > max_thread_id) {
    max_thread_id = thread;
  }

  assert(entry_id < (MAX_NUM_EVENTS - 1));
  (entry + 1)->action = ACTION_END;
}

void *ExecuteTraces(struct TraceThread *thread) {
  struct TraceEntry *entries = traces[thread->id];
  struct Heap *heap = thread->heap;
  int i = 0;
  for (; i < MAX_NUM_EVENTS; ++i) {
    assert(0 <= thread->id && thread->id < MAX_NUM_THREADS);

    struct TraceEntry *entry = &(entries[i]);
    switch (entry->action) {
      case ACTION_END:
        goto done;
      case ACTION_MALLOC:
        entry->malloc.address = Malloc(
            heap, (size_t) entry->malloc.malloc_size);
        if (!IsHeapAddress(heap, entry->malloc.address)) {
          printf(
              "BAD: Thread %d returned a bad pointer (%p) for malloc id %d "
              "of size %d. Trace line %d.\n", thread->id,
              entry->malloc.address, i, entry->malloc.malloc_size,
              entry->line);
        }
        thread->num_mallocs += 1.0;
        thread->total_malloc_time += GetElapsedTime();
        break;
      case ACTION_FREE: {
        struct TraceEntry *malloc = &(entries[entry->free.malloc_index]);

        if (!IsHeapAddress(heap, malloc->malloc.address)) {
          entry->free.expect_error = 1;
        }

        if (entry->free.expect_error) {
          printf(
              "NOTE: Expecting free in thread %d of malloc id %d to fail. "
              "Trace line %d.\n",
              thread->id, entry->free.malloc_index, entry->line);
          FreeFail(heap, malloc->malloc.address + entry->free.addr_skew,
                   malloc->malloc.malloc_size);
        } else {
          if (FREE_SUCCESS != Free(heap, malloc->malloc.address,
                                   malloc->malloc.malloc_size)) {
            printf(
                "BAD: Thread %d couldn't free malloc id %d of size %d that "
                "returned %p! Trace line %d.\n", thread->id,
                entry->free.malloc_index, malloc->malloc.malloc_size,
                malloc->malloc.address, entry->line);
          }
        }
        thread->num_frees += 1.0;
        thread->total_free_time += GetElapsedTime();
        break;
      }
      case ACTION_FREE_NULL:
        FreeFail(heap, NULL, 0);
        break;
    }
  }
done:
  return NULL;
}

int NumThreads(void) {
  return max_thread_id + 1;
}
