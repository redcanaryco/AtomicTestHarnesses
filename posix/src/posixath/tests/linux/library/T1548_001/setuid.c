#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

int main(int argc, char **argv)
{
    if(-1 == setuid(0))
    {
        perror("Failed to setuid to 0");
        return -1;
    }
    sleep(2);

    // I am root!
    return 0;
}