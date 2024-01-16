/*
  File: nscreateobjectfileimagefrommemory.c
  Author: Brandon Dalton
  Organization: Red Canary Threat Research
  Description: A simple stager/reflector to use in reflective loading tests.
  Compile: gcc -Wno-deprecated-declarations -o nscreateobjectfileimagefrommemory nscreateobjectfileimagefrommemory.c
  Usage: ./nscreateobjectfileimagefrommemory <path_to_bundle>
*/

#include <mach-o/dyld.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

void (*run_me)();

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <path_to_bundle>\n", argv[0]);
        return 1;
    }

    int fd = open(argv[1], O_RDONLY);
    struct stat stat_buf;
    fstat(fd, &stat_buf);
    void *file_memory = mmap(NULL, stat_buf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    
    NSObjectFileImage file_image;
    if (NSCreateObjectFileImageFromMemory(file_memory, stat_buf.st_size, &file_image) != NSObjectFileImageSuccess) {
        fprintf(stderr, "Failed to create object file image from memory\n");
        return 1;
    }

    NSModule module = NSLinkModule(file_image, argv[1], NSLINKMODULE_OPTION_PRIVATE | NSLINKMODULE_OPTION_RETURN_ON_ERROR);
    if (!module) {
        fprintf(stderr, "Failed to link module\n");
        return 1;
    }

    NSSymbol symbol = NSLookupSymbolInModule(module, "_run_me");
    if (!symbol) {
        fprintf(stderr, "Failed to locate symbol\n");
        return 1;
    }

    run_me = NSAddressOfSymbol(symbol);
    run_me();

    NSUnLinkModule(module, NSUNLINKMODULE_OPTION_NONE);
    munmap(file_memory, stat_buf.st_size);
    close(fd);

    return 0;
}