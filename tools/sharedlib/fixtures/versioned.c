int old_api(int value) { return value + 10; }
int new_api(int value) { return value + 20; }
__asm__(".symver old_api,api@LIBTEST_1");
__asm__(".symver new_api,api@@LIBTEST_2");
