#include <unistd.h>
#include <stdio.h>
#include <errno.h>

void main(){
    printf("%d\n", errno);
    fork();
    printf("%d\n", errno);
}
