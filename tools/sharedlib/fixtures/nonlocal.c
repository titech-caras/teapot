#include <setjmp.h>
#include <signal.h>
#include <stdlib.h>

static sigjmp_buf continuation;
static volatile sig_atomic_t state;
static void recover(int sig) {
    if (sig != SIGILL) abort();
    state = 42;
    siglongjmp(continuation, 7);
}
int library_probe(int x) {
    struct sigaction action = {0}, saved;
    sigset_t blocked, original, observed;
    action.sa_handler = recover;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGILL, &action, &saved)) abort();
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGUSR1);
    if (sigprocmask(SIG_BLOCK, &blocked, &original)) abort();
    state = 1;
    int resumed = sigsetjmp(continuation, 1);
    if (!resumed) {
        if (sigprocmask(SIG_UNBLOCK, &blocked, 0)) abort();
        raise(SIGILL);
        abort();
    }
    if (resumed != 7 || state != 42 || sigprocmask(SIG_BLOCK, 0, &observed) ||
        !sigismember(&observed, SIGUSR1)) abort();
    if (sigaction(SIGILL, &saved, 0) || sigprocmask(SIG_SETMASK, &original, 0)) abort();
    return x + (int)state;
}
