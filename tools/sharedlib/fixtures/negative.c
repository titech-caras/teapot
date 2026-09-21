#if defined(TLS_CASE)
__thread int feature = 1;
#elif defined(WEAK_CASE)
__attribute__((weak)) int feature(void) { return 1; }
#elif defined(PROTECTED_CASE)
__attribute__((visibility("protected"))) int feature(void) { return 1; }
#elif defined(IFUNC_CASE)
static int implementation(void) { return 1; }
static void *resolve(void) { return implementation; }
int feature(void) __attribute__((ifunc("resolve")));
#elif defined(LOOKUP_CASE)
#include <dlfcn.h>
void *feature(void) { return dlsym(RTLD_DEFAULT, "puts"); }
#elif defined(CTOR_CASE)
int feature;
__attribute__((constructor)) static void initialize(void) { feature = 1; }
#elif defined(DTOR_CASE)
int feature;
__attribute__((destructor)) static void finalize(void) { feature = 1; }
#elif defined(UNIQUE_CASE)
__asm__(".data\n.globl feature\n.type feature,@gnu_unique_object\nfeature:\n.long 1\n");
#elif defined(HOOK_CASE)
void __gmon_start__(void) {}
int feature(void) { return 1; }
#else
int feature(void) { return 1; }
#endif
