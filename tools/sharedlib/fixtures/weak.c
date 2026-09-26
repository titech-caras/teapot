extern int optional_value(void) __attribute__((weak));
extern int never_provided(void) __attribute__((weak));

int weak_probe(int caller)
{
    if (never_provided)
        return -1;
    return caller + (optional_value ? optional_value() : 100);
}
