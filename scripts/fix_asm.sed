s/^\.section \.NaHCO3_transient/&, "ax"/
s/^\.section \.NaHCO3_trampolines/&, "ax"/
s/^\.section \.NaHCO3_guards/&, "aw"/
s/^\.section \.NaHCO3_branch_counters/&, "aw"/
/^__guard_start__NaHCO3__:/i .globl __guard_start__NaHCO3__
/^__guard_end__NaHCO3__:/i .globl __guard_end__NaHCO3__
s/^\.symver/#\.symver/
