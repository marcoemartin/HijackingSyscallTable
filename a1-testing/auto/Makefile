
CC = gcc
CC_EXTRA_FLAGS = -O0 -g3 -Wall
CC_ERR_FLAGS = -Wno-format
MACRO_FLAGS = -Dmalloc=DoMalloc -Dcalloc=DoCalloc -Dfree=DoFree -Dsbrk=DoSbrk -Dmmap=DoMmap
CC_FLAGS = -I./ $(CC_ERR_FLAGS) $(CC_EXTRA_FLAGS)

CC_FILES = $(wildcard *.c)

# Compile C files to object files.
%.o :: %.c
	@echo "Building C object $@"
	@mkdir -p $(@D)
	@$(CC) $(CC_FLAGS) $(MACRO_FLAGS) -c $< -o $@


all: $(CC_FILES:.c=.o) 
	@echo "Building $@"
	@$(CC) -o a.out $^ -lpthread -lm -lrt

clean:
	@-rm $(wildcard *.o) a.out > /dev/null 2>&1 ||:
	#@-rm log/*  > /dev/null 2>&1 ||:
