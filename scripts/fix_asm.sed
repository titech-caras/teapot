# No longer part of Teapot's pipeline: the pinned gtirb-pprinter prints these section
# flags and the guard bounds' .globl itself, so this script changes nothing but a
# duplicate .globl. It stays only for external harnesses that still run it; delete it
# together with them.
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
