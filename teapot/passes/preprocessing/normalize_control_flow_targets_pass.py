import gtirb
from gtirb_rewriting import Pass, RewritingContext


class NormalizeControlFlowTargetsPass(Pass):
    """Anchor movable direct-control-flow expressions to their CFG target.

    A lifted branch can be represented as ``function_symbol + offset`` even
    when its CFG edge points at a distinct basic block.  That expression is
    equivalent in the original layout, but the fixed offset becomes stale if
    rewriting inserts bytes between the function entry and the destination.

    Normalize only simple direct branches and calls whose symbolic expression
    already resolves exactly to one concrete CFG destination.  This keeps the
    change semantic-preserving and leaves indirect, unresolved, specially
    relocated, and non-control-flow expressions alone.
    """

    _EDGE_TYPES = {
        gtirb.cfg.Edge.Type.Branch,
        gtirb.cfg.Edge.Type.Call,
    }
    _SAFE_ATTRIBUTES = {
        gtirb.SymbolicExpression.Attribute.PCREL,
    }
    _SYMBOL_PREFIX = ".L__teapot_cf_target_"

    def __init__(self, decoder):
        self.decoder = decoder
        self.normalized = 0

    def begin_module(
        self,
        module: gtirb.Module,
        functions,
        rewriting_ctx: RewritingContext,
    ) -> None:
        self.normalized = 0
        self._symbol_names = {symbol.name for symbol in module.symbols}
        self._target_symbols = {}

        for block in module.code_blocks:
            targets = self._direct_targets(block)
            if not targets or block.address is None or block.byte_interval is None:
                continue

            last_instruction = self._last_instruction(block)
            if last_instruction is None:
                continue

            interval = block.byte_interval
            instruction_offset = block.offset + last_instruction.address - block.address
            for offset in range(
                instruction_offset,
                instruction_offset + last_instruction.size,
            ):
                expression = interval.symbolic_expressions.get(offset)
                if not self._is_simple_address(expression):
                    continue

                expression_address = self._expression_address(expression)
                matching_targets = targets.get(expression_address, ())
                if len(matching_targets) != 1:
                    continue

                target = next(iter(matching_targets))
                if self._already_exact(expression, target):
                    continue

                interval.symbolic_expressions[offset] = gtirb.SymAddrConst(
                    offset=0,
                    symbol=self._target_symbol(module, target),
                    attributes=set(expression.attributes),
                )
                self.normalized += 1

    def end_module(self, module, functions) -> None:
        print(
            "[teapot] NormalizeControlFlowTargetsPass normalized "
            f"{self.normalized} expressions",
            flush=True,
        )

    def _direct_targets(self, block):
        targets = {}
        for edge in block.outgoing_edges:
            label = edge.label
            target = edge.target
            if (
                label is None
                or label.type not in self._EDGE_TYPES
                or not label.direct
                or not isinstance(target, gtirb.CodeBlock)
                or target.address is None
            ):
                continue
            targets.setdefault(target.address, set()).add(target)
        return targets

    def _last_instruction(self, block):
        last_instruction = None
        for instruction in self.decoder.get_instructions(block):
            last_instruction = instruction
        return last_instruction

    def _is_simple_address(self, expression) -> bool:
        return (
            isinstance(expression, gtirb.SymAddrConst)
            and expression.attributes.issubset(self._SAFE_ATTRIBUTES)
        )

    @classmethod
    def _expression_address(cls, expression):
        symbol_address = cls._symbol_address(expression.symbol)
        if symbol_address is None:
            return None
        return symbol_address + expression.offset

    @staticmethod
    def _symbol_address(symbol):
        if symbol.value is not None:
            return symbol.value

        referent = symbol.referent
        address = getattr(referent, "address", None)
        if address is None:
            return None
        if not symbol.at_end:
            return address

        size = getattr(referent, "size", None)
        if size is None:
            return None
        return address + size

    @staticmethod
    def _already_exact(expression, target) -> bool:
        return (
            expression.offset == 0
            and expression.symbol.referent is target
            and not expression.symbol.at_end
        )

    def _target_symbol(self, module, target):
        cached = self._target_symbols.get(target)
        if cached is not None:
            return cached

        existing = sorted(
            (
                symbol
                for symbol in target.references
                if symbol.name and not symbol.at_end
            ),
            key=lambda symbol: (symbol.name, symbol.uuid.hex),
        )
        if existing:
            self._target_symbols[target] = existing[0]
            return existing[0]

        base_name = self._SYMBOL_PREFIX + target.uuid.hex
        name = base_name
        suffix = 0
        while name in self._symbol_names:
            suffix += 1
            name = f"{base_name}_{suffix}"

        symbol = gtirb.Symbol(name=name, payload=target, module=module)
        self._symbol_names.add(name)
        self._target_symbols[target] = symbol
        return symbol
