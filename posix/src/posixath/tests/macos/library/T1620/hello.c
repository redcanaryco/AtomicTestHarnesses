/*
  File: hello.c
  Author: Brandon Dalton
  Organization: Red Canary Threat Research
  Description: A simple bundle to use in in reflective loading tests.
  Compile: gcc -o libhello.bundle hello.c -bundle
*/

#include <stdio.h>

void run_me() {
    printf("👋 Hello curious user!\n");
}