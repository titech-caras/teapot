/^\.section \.teapot_transient\([[:space:],]\|$\)/{
/"ax"/! s/^\.section \.teapot_transient/&, "ax"/
}
/^\.section \.teapot_trampolines\([[:space:],]\|$\)/{
/"ax"/! s/^\.section \.teapot_trampolines/&, "ax"/
}
/^\.section \.teapot_guards\([[:space:],]\|$\)/{
/"aw"/!{
/"wa"/! s/^\.section \.teapot_guards/&, "aw"/
}
}
/^\.section \.teapot_branch_counters\([[:space:],]\|$\)/{
/"aw"/!{
/"wa"/! s/^\.section \.teapot_branch_counters/&, "aw"/
}
}
/^__guard_start__teapot__:/i .globl __guard_start__teapot__
/^__guard_end__teapot__:/i .globl __guard_end__teapot__
s/^\.symver/#\.symver/
