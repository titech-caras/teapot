s/^\.section \.teapot_transient/&, "ax"/
s/^\.section \.teapot_trampolines/&, "ax"/
s/^\.section \.teapot_guards/&, "aw"/
s/^\.section \.teapot_branch_counters/&, "aw"/
/^__guard_start__teapot__:/i .globl __guard_start__teapot__
/^__guard_end__teapot__:/i .globl __guard_end__teapot__
s/^\.symver/#\.symver/
