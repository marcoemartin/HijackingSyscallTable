/* Copyright 2014 Peter Goodman, all rights reserved. */

#ifndef LAB1_TEST_TRACE_H_
#define LAB1_TEST_TRACE_H_

#include <stddef.h>

#include "test_heap.h"

enum {
  MAX_NUM_THREADS = 10,
  MAX_NUM_EVENTS = 10000
};

struct TraceEntry {
  enum {
    ACTION_END, ACTION_MALLOC, ACTION_FREE, ACTION_FREE_NULL
  } action;

  int line;

  union {
    struct {
      int malloc_size;
      char *address;
    } malloc;

    struct {
      int expect_error;  // Do we expect an error?
      int addr_skew;  // Used to introduce faults into the program.
      int malloc_index;  // Used to find the malloc associated with this free.
    } free;
  };
};

struct TraceThread {
  struct Heap *heap;
  int id;
  double total_malloc_time;
  double total_free_time;
  double num_mallocs;
  double num_frees;
};

void ParseTraceLine(const char *line, int line_num);

void *ExecuteTraces(struct TraceThread *thread);

int NumThreads(void);

#endif  // LAB1_TEST_TRACE_H_
