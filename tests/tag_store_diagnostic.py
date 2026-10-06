"""Fixture-only instrumentation of the *existing* replay old-load and store.

No product or runtime change. This mixin surrounds the production volatile
operations; it never reads shadow itself, never suppresses a store, and puts
counters in a dedicated non-rollback array. Site IDs are fixture-local.
"""

FIELDS = ('load_attempts', 'comparisons', 'equal', 'different',
          'store_attempts', 'store_completions', 'mutation_attempts',
          'mutation_completions')
WIDTHS = (1, 2, 4, 8)
MAX_SITES = 16
COUNTERS = MAX_SITES * len(WIDTHS) * len(FIELDS)


class TagStoreCountingMixin:
    REPLAY_SYMBOLS = frozenset({'tag_store_diagnostic'})

    def _format_llvm_ir(self, body, *, target_triple=None):
        ir = super()._format_llvm_ir(body, target_triple=target_triple)
        return ir.replace('define dso_local void @func',
                          f'@tag_store_diagnostic = external dso_local global [{COUNTERS} x i64]\n'
                          'define dso_local void @func')

    def _count(self, width, field, increment=1):
        index = (self.diagnostic_site * len(WIDTHS) + WIDTHS.index(width)) * len(FIELDS) + FIELDS.index(field)
        ptr = self._build_gep('i64', 'tag_store_diagnostic', index,
                              ptr_type=f'[{COUNTERS} x i64]')
        old = super()._load('i64', ptr, volatile=True, align=8)
        value = self._add('i64', old, increment)
        super()._store('i64', value, ptr, volatile=True, align=8)

    def _load(self, type, address, *, dift_mem=False, **kwargs):
        if dift_mem and kwargs.get('volatile'):
            width = int(type[1:]) // 8
            self._count(width, 'load_attempts')
        value = super()._load(type, address, dift_mem=dift_mem, **kwargs)
        if dift_mem and kwargs.get('volatile'):
            self._diagnostic_old = (type, address, value)
        return value

    def _store(self, type, value, address, *, dift_mem=False, **kwargs):
        if not dift_mem or not kwargs.get('volatile'):
            return super()._store(type, value, address, dift_mem=dift_mem, **kwargs)
        old_type, old_address, old = self._diagnostic_old
        assert (type, address) == (old_type, old_address)
        width = int(type[1:]) // 8
        # The value is exactly the production broadcast/truncation at this
        # width, and old is exactly the production volatile old-value load.
        equal = self._icmp('eq', type, value, old)
        unequal = self._build_inst(f'xor i1 {equal}, true')
        equal_count = self._build_inst(f'zext i1 {equal} to i64')
        changed_count = self._build_inst(f'zext i1 {unequal} to i64')
        self._count(width, 'comparisons')
        self._count(width, 'equal', equal_count)
        self._count(width, 'different', changed_count)
        self._count(width, 'store_attempts')
        self._count(width, 'mutation_attempts', changed_count)
        super()._store(type, value, address, dift_mem=True, **kwargs)
        self._count(width, 'store_completions')
        self._count(width, 'mutation_completions', changed_count)


def counting_replay(arch, manager, **kwargs):
    from teapot.passes.transient.lazy_dift import transient_replay_pass
    replay = transient_replay_pass(arch, manager, None, None, **kwargs)
    base = type(replay)
    cls = type('Counting' + base.__name__, (TagStoreCountingMixin, base), {
        'REPLAY_SYMBOLS': base.REPLAY_SYMBOLS | {'tag_store_diagnostic'}})
    replay.__class__ = cls
    replay.diagnostic_site = 0
    return replay
