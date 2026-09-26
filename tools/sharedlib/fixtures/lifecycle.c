#include <stdio.h>
#include <stdlib.h>

static int state;
static void ctor_exit(void) { printf("library constructor exit state=%d\n", state); }
static void main_exit(void) { printf("library main exit state=%d\n", state); }
#ifdef TEST_ARRAY_STARTUP
__attribute__((constructor(101)))
#endif
void library_init(int argc, char **argv, char **envp) {
    if (argc < 1 || !argv || !argv[0] || !envp) abort();
    state = 1;
    puts("library DT_INIT");
}
__attribute__((constructor(201))) static void first(int argc, char **argv, char **envp) {
    if (state != 1 || argc < 1 || !argv[0] || !envp) abort();
    state = 2;
    puts("library constructor 201");
    if (atexit(ctor_exit)) abort();
}
__attribute__((constructor(202))) static void second(void) {
    if (state != 2) abort();
    state = 3;
    puts("library constructor 202");
}
__attribute__((destructor(201))) static void final_first(void) {
    puts("library destructor 201");
}
__attribute__((destructor(202))) static void final_second(void) {
    puts("library destructor 202");
}
#ifdef TEST_ARRAY_STARTUP
__attribute__((destructor(101)))
#endif
void library_fini(void) { puts("library DT_FINI"); }
int library_use(int x) {
    if (state != 3 || atexit(main_exit)) abort();
    state = 4;
    return x + 40;
}
