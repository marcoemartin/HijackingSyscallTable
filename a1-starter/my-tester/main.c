#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <signal.h>
#include <errno.h>

int main(int argc, char *argv[])
{
    int i = syscall(0,0,100,0,0);
    printf("%d\n",i);
    if (i == -1)
        printf("%d\n",errno);
    return 0;
}
