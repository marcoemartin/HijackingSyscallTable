#include <stdio.h>
#include <time.h>

struct timespec start, end;

void StartClock(void) {
  int result = clock_gettime(CLOCK_REALTIME, &start);
  if(result == -1) {
	  perror("clock_gettime");
  }
}

void EndClock(void) {
  int result = clock_gettime(CLOCK_REALTIME, &end);
  if(result == -1) {
	  perror("clock_gettime");
  }

}

double GetElapsedTime(void) {
  double diff = (end.tv_sec - start.tv_sec) * 1000000000 + (end.tv_nsec - start.tv_nsec);
  return diff;
}
