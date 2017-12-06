# Trace Format:
#
#   m <thread id> <thread-specific malloc id> <num bytes>
#   f <thread id> <thread-specific malloc id>

import sys
import random

num_threads = int(sys.argv[1])
max_num_events_per_thread = 1000
max_sbrk_size_pages = 8190
page_size_bytes = 4096
max_heap_size = int((max_sbrk_size_pages * 0.6) * page_size_bytes)
min_alloc_size = 4
max_alloc_size = 8192

events = [[] for i in range(num_threads)]
schedule = []
alloc_sizes = []
malloc_ids = [set() for t in range(num_threads)]
next_event_id = [0] * num_threads

for t in range(num_threads):
  for e in range(max_num_events_per_thread):
    schedule.append(t)

random.shuffle(schedule)

while max_heap_size > min_alloc_size:
  alloc_size = random.randint(min_alloc_size, max_alloc_size)
  max_heap_size = max_heap_size - alloc_size
  alloc_sizes.append(alloc_size)

random.shuffle(alloc_sizes)

for t in schedule:
  event_id = next_event_id[t]
  next_event_id[t] += 1

  if malloc_ids[t] and not random.randint(0, 1):
    print "f", t, malloc_ids[t].pop()
  elif alloc_sizes:
    print "m", t, event_id, alloc_sizes.pop()
    malloc_ids[t].add(event_id)
  else:
    break
