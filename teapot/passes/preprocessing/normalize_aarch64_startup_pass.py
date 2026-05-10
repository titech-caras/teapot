import gtirb
from capstone import CS_OP_IMM, CS_OP_REG
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_rewriting import Pass, Patch, RewritingContext, patch_constraints

from teapot.arch.aarch64.architecture import AArch64Architecture


class NormalizeAArch64StartupPass(Pass):
    """Replace crt _start absolute entry-point immediates with symbols."""

    def __init__(self, decoder: GtirbInstructionDecoder):
        self.decoder = decoder

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext) -> None:
        if module.isa != gtirb.Module.ISA.ARM64:
            return

        symbols = {symbol.name: symbol for symbol in module.symbols}
        start_symbol = symbols.get("_start")
        main_symbol = symbols.get("main")
        init_symbol = symbols.get("__libc_csu_init")
        fini_symbol = symbols.get("__libc_csu_fini")
        if None in (start_symbol, main_symbol, init_symbol, fini_symbol):
            return

        start_block = getattr(start_symbol, "referent", None)
        if not isinstance(start_block, gtirb.CodeBlock) or start_block.address is None:
            return

        target_values = (
            ("x0", self._symbol_address(main_symbol), "main"),
            ("x3", self._symbol_address(init_symbol), "__libc_csu_init"),
            ("x4", self._symbol_address(fini_symbol), "__libc_csu_fini"),
        )
        if any(address is None for _, address, _ in target_values):
            return

        instructions = list(self.decoder.get_instructions(start_block))
        for idx in range(0, len(instructions) - 12):
            first = instructions[idx]
            matched = True
            for seq_idx, (register, address, _) in enumerate(target_values):
                sequence = instructions[idx + seq_idx * 4: idx + (seq_idx + 1) * 4]
                if self._mov_address_sequence(sequence, register) != address:
                    matched = False
                    break

            if not matched or instructions[idx + 12].mnemonic != "bl":
                continue

            patch_offset = first.address - start_block.address
            patch_size = sum(inst.size for inst in instructions[idx: idx + 12])
            rewriting_ctx.replace_at(
                start_block,
                patch_offset,
                patch_size,
                Patch.from_function(self._startup_symbols_patch(
                    target_values[0][2],
                    target_values[1][2],
                    target_values[2][2],
                )),
            )
            return

    @staticmethod
    def _symbol_address(symbol):
        referent = getattr(symbol, "referent", None)
        if referent is None:
            return None
        return getattr(referent, "address", None)

    @staticmethod
    def _startup_symbols_patch(main: str, init: str, fini: str):
        @patch_constraints()
        def patch(ctx):
            return f"""
            {AArch64Architecture.load_address("x0", main)}
            {AArch64Architecture.load_address("x3", init)}
            {AArch64Architecture.load_address("x4", fini)}
        """

        return patch

    @staticmethod
    def _mov_address_sequence(instructions, register: str):
        if len(instructions) != 4:
            return None

        value = 0
        expected = ("movz", "movk", "movk", "movk")
        for inst, mnemonic in zip(instructions, expected):
            if inst.mnemonic != mnemonic:
                return None
            if len(inst.operands) < 2:
                return None

            reg_operand, imm_operand = inst.operands[:2]
            if reg_operand.type != CS_OP_REG or inst.reg_name(reg_operand.reg) != register:
                return None
            if imm_operand.type != CS_OP_IMM:
                return None

            shift = imm_operand.shift.value if imm_operand.shift.type else 0
            value |= (imm_operand.imm & 0xffff) << shift

        return value
