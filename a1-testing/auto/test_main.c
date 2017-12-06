/* Copyright 2014 Peter Goodman, all rights reserved. */

#include <errno.h>
#include <execinfo.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "test_heap.h"
#include "test_trace.h"

// Mutex that can be used by course code.
pthread_mutex_t mywait;
void *start_heap = NULL;
void *max_heap = 0;

// Manages trace threads.
static pthread_t threads[MAX_NUM_THREADS];
static struct TraceThread trace_threads[MAX_NUM_THREADS];

// Heap used by `mem_sbrk`.
static struct Heap *heap;

// Optional heap initialization function that teams can use.
extern int myinit(void) __attribute__((weak));

// Stub for the system `sbrk` that re-routes everything through `heap`.
void *DoSbrk(intptr_t size) {
  return ShiftBreak(heap, size);
}

// Stub for mmap.
void *DoMmap(void *x, ...) {
  printf("BAD: Program used libc `mmap` instead of `sbrk`.\n");
  errno = ENOMEM;
  (void) x;
  return (void *) -1;
}

void *DoMalloc(size_t size) {
  printf("BAD: Program used libc `malloc`.\n");
  errno = ENOMEM;
  (void) size;
  return NULL;
}

void *DoCalloc(size_t num, size_t size) {
  printf("BAD: Program used libc `calloc`.\n");
  errno = ENOMEM;
  (void) num; (void) size;
  return NULL;
}

void DoFree(void *ptr) {
  printf("BAD: Program used libc `free`.\n");
  (void) ptr;
}

// Simple configuration of the heap. No debugging performed.
static void ConfigSimple(struct HeapOptions *options) {
  options->use_reentrant_sbrk = 1;

  options->uninit_poison_val = 0x33;
  options->init_poison_val = 0xAA;
  options->malloc_poison_val = 0x77;
  options->free_poison_val = 0xDE;
}

// Parses the lines of the trace file.
static void ParseTraceFile(FILE *fp) {
  char line_buff[32] = {'\0'};
  int line = 1;
  while (NULL != fgets(line_buff, 31, fp)) {
    line_buff[31] = '\0';
    ParseTraceLine(line_buff, line++);
    line_buff[0] = '\0';
  }
}

// Loads the trace file.
static void LoadTraceFile(const char *file_name) {
  FILE *trace_file = NULL;
  if (NULL == (trace_file = fopen(file_name, "r"))) {
    fprintf(stderr, "Unable to open trace file '%s' for reading.\n", file_name);
    exit(EXIT_FAILURE);
  }
  ParseTraceFile(trace_file);
  fclose(trace_file);
}

// Handle timeouts.
static void Timeout(int sig) {
  printf("BAD: Program hung. 1 second timeout exceeded.\n");
  exit(EXIT_FAILURE);
}

// Show a stack trace on a SIGSEGV or a SIGABRT.
//
// From: http://www.emoticode.net/c/custom-sigsegv-handler-with-backtrace-reporting.html
static void DumpStack(int sig) {
  void *trace[32];
  size_t size, i;
  char **strings;

  if (SIGSEGV == sig) {
    printf("\n********* SEGMENTATION FAULT *********\n\n");
  } else if (SIGABRT == sig) {
    printf("\n********* ASSERTION FAILURE **********\n\n");
  }

  size = backtrace(trace, 32);
  strings = backtrace_symbols(trace, size);

  printf("\nBACKTRACE:\n\n");
  for (i = 0; i < size; i++) {
    printf("  %s\n", strings[i]);
  }

  printf("\n***************************************\n");

  exit(EXIT_FAILURE);
}

// Runs an experiment.
int main(int argc, const char *argv[]) {
  int tid = 0;
  int num_threads = 0;
  double total, count;

  // Catch timeouts and faults.
  signal(SIGALRM, Timeout);
  signal(SIGSEGV, DumpStack);
  signal(SIGABRT, DumpStack);
  alarm(1);

  memset(&trace_threads, 0, sizeof trace_threads);
  memset(&threads, 0, sizeof threads);

  if (2 != argc) {
    fprintf(stderr, "Usage: %s trace_file\n", argv[0]);
    return EXIT_FAILURE;
  }

  // Setup.
  pthread_mutex_init(&mywait, NULL);
  LoadTraceFile(argv[1]);
  heap = AllocHeap(33546240 /* 32 MiB - 2 redzone pages */, ConfigSimple);
  start_heap = heap->sbrk;

  printf("Trace Output ================================================\n\n");

  if (myinit) myinit();

  num_threads = NumThreads();
  for (tid = 0; tid < num_threads; ++tid) {
    trace_threads[tid].heap = heap;
    trace_threads[tid].id = tid;
    pthread_create(&(threads[tid]), NULL, (void *(*)(void *)) ExecuteTraces,
                   &(trace_threads[tid]));
  }

  for (tid = 0; tid < num_threads; ++tid) {
    pthread_join(threads[tid], NULL);
  }

  printf("\n\n");

  printf("Memory Report ===============================================\n\n");
  Report(heap);
  printf("\n\n");
  printf("Time Report =================================================\n\n");
  total = 0.0;
  count = 0.0;
  for (tid = 0; tid < num_threads; ++tid) {
    total += trace_threads[tid].total_malloc_time;
    count += trace_threads[tid].num_mallocs;
  }
  printf("Total time spent on `mymalloc`: %lfs.\n", total);
  printf("Average `mymalloc` time: %lfs.\n", total / count);

  total = 0.0;
  count = 0.0;
  for (tid = 0; tid < num_threads; ++tid) {
    total += trace_threads[tid].total_free_time;
    count += trace_threads[tid].num_frees;
  }
  printf("Total time spent on `myfree`: %lfs.\n", total);
  printf("Average `myfree` time: %lfs.\n", total / count);

  // Teardown.
  FreeHeap(heap);
  return EXIT_SUCCESS;
}
