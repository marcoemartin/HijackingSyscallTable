/* This file contains example invocations of mymalloc and myfree.
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <pthread.h>

#define MAX_THREADS 10
#define MAX_OPS 25000
#define MAX_LOC MAX_OPS/2

/* Credit: 
 * http://stackoverflow.com/questions/1644868/c-define-macro-for-debug-printing 
 */
#define DEBUG 1
#define debug_print(fmt, ...) \
            do { if (DEBUG) fprintf(stdout, fmt, __VA_ARGS__); } while (0)

/* Prototypes */
void *mymalloc(unsigned int size); // Returns NULL on error.
unsigned int myfree(void *ptr);    // Returns 0 on success and >0 on error.

/* Global variables */
pthread_mutex_t mywait;

void *start_heap;
void *max_heap = 0;
#define check_heap() \
            if (max_heap < sbrk(0)) { max_heap = sbrk(0); }

/* The arrays that hold the trace information are statically
 * allocated because using the libc malloc would interfere 
 * using mymalloc.
 */
struct trace_op {
    enum {MALLOC, FREE} type;
    int index; // for myfree() to use later 
    int size;
};

struct trace {
    int num_locations; // do we need this?
    int num_ops;
    struct trace_op ops[MAX_OPS];
    char *blocks[MAX_LOC];
    int sizes[MAX_LOC];
};

struct trace ttrace[MAX_THREADS];

/* Each thread executes the operations from its own array
*/
void *dowork(void *threadid) {
    long id = (long)threadid;
    int i;
    char *ptr;
    struct trace tr = ttrace[id];
    int ops = tr.num_ops;
    
    for (i = 0; i < ops; i++) {
        switch(tr.ops[i].type) {
            case MALLOC:
                debug_print("thread%li: malloc block %d (size %d)\n", id, tr.ops[i].index, tr.ops[i].size);
                tr.blocks[tr.ops[i].index] = mymalloc(tr.ops[i].size);
                debug_print("Thread%li: malloc returned pointer %p for size %d\n", id, 
                    tr.blocks[tr.ops[i].index], tr.ops[i].size);
                if (!tr.blocks[tr.ops[i].index]) {
                    fprintf(stderr, "Thread %li reported an error on allocation %i.\n", 
                            id, tr.ops[i].index);
                }
                break;

            case FREE:
                ptr = tr.blocks[tr.ops[i].index];
                debug_print("thread%li: free block %d at pointer %p\n", id, tr.ops[i].index, ptr);
                if(myfree(ptr)) {
                    fprintf(stderr, "Thread%li reported an error on free (block %d).\n", 
                            id, tr.ops[i].index);
                }
                break;
            default:
                fprintf(stderr, "Error: bad instruction\n");
                exit(1);
        }
    }
    
    pthread_exit(NULL);
}

/* read_trace reads the data from the open file fp and populates
 * the global variable ttrace */
int load_trace(FILE *fp) {  
    int i;
    int thread;
    int index;
    int size;
    int ci;
    char type[10];
    int max_thread = 0;

    for(i = 0; i < MAX_THREADS; i++) {
        ttrace[i].num_ops = 0;
    }

    while(fscanf(fp, "%s", type) !=EOF) {
        switch(type[0]) {
            case 'm':
                fscanf(fp, "%u %u %u", &thread, &index, &size);
                ci = ttrace[thread].num_ops;
                ttrace[thread].ops[ci].type = MALLOC;
                ttrace[thread].ops[ci].index = index;
                ttrace[thread].ops[ci].size = size;
                ttrace[thread].num_ops++;
                break;
            case 'f':
                fscanf(fp, "%u %u", &thread, &index);
                ci = ttrace[thread].num_ops;
                ttrace[thread].ops[ci].type = FREE;
                ttrace[thread].ops[ci].index = index;
                ttrace[thread].num_ops++;
                break;
            default:
                fprintf(stderr, "Bad type (%c) in trace file\n", type[0]);
                exit(1);
        }
        max_thread = thread > max_thread ? thread : max_thread;
    }
    fclose(fp);
    return(max_thread + 1);
}

/* Example main function that invokes mymalloc and myfree.
*/
int main(int argc, char *argv[]) {
    pthread_t threads[MAX_THREADS];
    long tid;
    int err = 0;

    struct timeval start, end;
    double diff;

    FILE *fp;

    if(argc != 2) {
        printf("Usage: %s trace_file\n", argv[0]);
        exit(1);
    }

    if((fp = fopen(argv[1], "r")) == NULL) {
        perror("Trace file open:");
        exit(1);
    }
    int num_threads = load_trace(fp);

    if (pthread_mutex_init(&mywait, NULL)) {
        fprintf(stderr, "Error: mutex initialization failed.\n");
        return 1;
    }

    start_heap = sbrk(0);
    
    gettimeofday(&start, NULL);
    for (tid = 0; tid < num_threads; tid++) {
        err = pthread_create(&threads[tid], NULL, dowork, (void *)tid);
        if (err) {
            fprintf(stderr, "Error: pthread_create failed on dowork thread %li.\n", tid);
            return 1;
        }
    }

    for (tid = 0; tid < num_threads; tid++) {
        err = pthread_join(threads[tid], NULL);
        if(err) {
            fprintf(stderr, "Error: pthread_join failed on thread %li.\n", tid);
        }
    }
    gettimeofday(&end, NULL);
    diff = 1000000 *(end.tv_sec - start.tv_sec) 
            + (end.tv_usec - start.tv_usec);
    fprintf(stdout, "Time: %f\n", diff);
    check_heap();
    fprintf(stdout, "Max heap extent: %lu\n", max_heap - start_heap);
    
    return 0;
}
