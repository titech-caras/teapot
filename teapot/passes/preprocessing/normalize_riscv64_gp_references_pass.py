from collections import defaultdict
import warnings

import gtirb
from capstone import CS_OP_IMM, CS_OP_MEM, CS_OP_REG
from gtirb_rewriting import Pass, Patch, RewritingContext
from gtirb_rewriting.assembly import Constraints


class NormalizeRISCV64GPReferencesPass(Pass):
    """Expand small-data references before their scratch saves are instrumented.

    Ordinary stack spills are valid here because later passes see their memory
    effects in both copies. Runtime instrumentation must still use the spill ABI.
    PC-relative relocations remain range-checked by the assembler/linker; never
    truncate a moved GP displacement to twelve bits.
    """

    def __init__(self, decoder, reg_manager, arch):
        self.decoder = decoder
        self.reg_manager = reg_manager
        self.arch = arch
        self.normalized = self.reused = self.spare = self.spilled = 0

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext):
        unresolved = module.aux_data.get("riscvUnresolvedPcrelReferences")
        if unresolved is None:
            warnings.warn(
                f"RV64 module {module.name!r} lacks riscvUnresolvedPcrelReferences; "
                "absence does not establish that PC-relative references were checked. "
                "Regenerate the input with the current ddisasm.", RuntimeWarning, stacklevel=2)
        if unresolved is not None and unresolved.data:
            # These are original input addresses, not offsets to update during
            # rewriting. Refuse before relayout can invalidate the numeric pair.
            pairs = "; ".join(f"{high:#x} -> {low:#x}: {reason}"
                              for high, low, reason in sorted(unresolved.data))
            raise ValueError(f"RV64 input has unresolved PC-relative references: {pairs}. "
                             "Resolve the frontend symbolization before rewriting.")

        block_functions = defaultdict(list)
        for function in functions:
            for block in function.get_all_blocks():
                block_functions[block].append(function)

        # Overlapping blocks can describe the same instruction. Replace it once,
        # and require a spare to be dead in every available view of that site.
        sites = defaultdict(list)
        for block in module.code_blocks:
            if not block.size:
                continue
            for index, inst in enumerate(self.decoder.get_instructions(block)):
                if block.address is None:
                    if self._uses_gp_address(inst):
                        raise ValueError("RV64 GP normalization requires instruction addresses")
                    continue
                offset = block.offset + inst.address - block.address
                expression = block.byte_interval.symbolic_expressions.get(offset)
                gp_expression = (isinstance(expression, gtirb.SymAddrAddr) and
                                 expression.symbol2.name == "__global_pointer$")
                # The whole pass, and the frontend symbolization it depends on,
                # assume gp holds __global_pointer$ for the life of the process.
                # An unsymbolized write to gp breaks that silently, so refuse it
                # rather than rewrite other references against a stale base.
                if (self._writes_global_pointer(inst) and expression is None
                        and not self._uses_gp_address(inst)):
                    raise ValueError(
                        f"RV64 GP normalization found an unmodeled write to gp at "
                        f"{inst.address:#x}: {inst.mnemonic} {inst.op_str}. This pass and the "
                        "frontend's gp symbolization both assume gp stays constant after "
                        "initialization.")
                if not gp_expression and not self._uses_gp_address(inst):
                    continue
                sites[block.byte_interval, offset].append((block, index, inst))

        for (interval, offset), views in sorted(sites.items(), key=lambda item: item[1][0][2].address):
            block, index, inst = views[0]
            expression = interval.symbolic_expressions.get(offset)
            if isinstance(expression, gtirb.SymAddrConst):
                # A GP-based LO from an actual AUIPC/LUI pair is already symbolic,
                # including the GP initialization itself; it is not small data.
                continue
            if not (isinstance(expression, gtirb.SymAddrAddr) and expression.scale == 1 and
                    expression.symbol2.name == "__global_pointer$" and
                    expression.attributes.issubset({gtirb.SymbolicExpression.Attribute.LO})):
                raise ValueError(
                    f"RV64 GP reference at {inst.address:#x} lacks supported symbolic metadata: "
                    f"{inst.mnemonic} {inst.op_str}")
            if any(bytes(other.bytes) != bytes(inst.bytes) for _, _, other in views):
                raise ValueError(f"Ambiguous overlapping RV64 GP instruction at {inst.address:#x}")
            if not self._uses_gp_address(inst):
                raise ValueError(f"RV64 GP metadata does not match the operand at {inst.address:#x}")

            free = set(self.arch.abi._scratch_registers())
            for view_block, view_index, _ in views:
                if self.reg_manager is None or not block_functions[view_block]:
                    free.clear()
                    break
                for function in block_functions[view_block]:
                    self.reg_manager.analyze(function)
                    free.intersection_update(self.reg_manager.free_registers(function, view_block, view_index))

            assembly = self._replacement(inst, expression, free)
            rewriting_ctx.replace_at(
                block, offset - block.offset, inst.size,
                Patch.from_function(lambda _ctx, assembly=assembly: assembly, Constraints()))
            self.normalized += 1

    def _writes_global_pointer(self, inst) -> bool:
        gp = self.arch.abi.get_register("gp")
        if gp is None:
            return False
        return gp in self.arch.access_registers(self.arch.abi, inst, 1)

    @staticmethod
    def _uses_gp_address(inst):
        if any(op.type == CS_OP_MEM and inst.reg_name(op.mem.base) == "gp" for op in inst.operands):
            return True
        if inst.mnemonic == "addi" and len(inst.operands) == 3:
            return inst.operands[1].type == CS_OP_REG and inst.reg_name(inst.operands[1].reg) == "gp"
        if inst.mnemonic in {"mv", "c.mv"} and len(inst.operands) == 2:
            return inst.operands[1].type == CS_OP_REG and inst.reg_name(inst.operands[1].reg) == "gp"
        return (inst.mnemonic == "c.addi" and inst.operands and
                inst.operands[0].type == CS_OP_REG and inst.reg_name(inst.operands[0].reg) == "gp")

    def _replacement(self, inst, expression, free):
        mnemonic = self.arch.bare_mnemonic(inst.mnemonic)
        operands = inst.operands
        if not operands or operands[0].type != CS_OP_REG:
            raise ValueError(f"Unsupported RV64 GP operand at {inst.address:#x}")
        value = inst.reg_name(operands[0].reg)
        load = self.arch.is_load_mnemonic(mnemonic)
        store = self.arch.is_store_mnemonic(mnemonic)
        address = (mnemonic == "addi" and operands[-1].type == CS_OP_IMM) or mnemonic == "mv"
        if not (load or store or address):
            raise ValueError(f"Unsupported RV64 GP instruction: {inst.mnemonic} {inst.op_str}")

        target = gtirb.SymAddrConst(expression.offset, expression.symbol1, {
            gtirb.SymbolicExpression.Attribute.PCREL, gtirb.SymbolicExpression.Attribute.HI})
        if address and value == "zero":
            self.reused += 1
            return "nop"

        destination = self.arch.register_from_name(self.arch.abi, value)
        reusable = (not store and destination is not None and
                    destination not in {self.arch.abi.get_register(name) for name in ("sp", "gp", "tp")})
        candidates = [reg for reg in self.arch.abi._scratch_registers()
                      if not store or destination is None or reg != destination]
        scratch = destination if reusable else next((reg for reg in candidates if reg in free), None)
        spilled = scratch is None
        if spilled:
            scratch = candidates[0]
            self.spilled += 1
        elif reusable:
            self.reused += 1
        else:
            self.spare += 1

        prologue, epilogue = "", ""
        if spilled:
            prologue = f"addi sp, sp, -16\nsd {scratch}, 0(sp)\n"
            epilogue = f"ld {scratch}, 0(sp)\naddi sp, sp, 16\n"
            if value == "sp":
                other = next(reg for reg in candidates if reg != scratch)
                prologue += f"sd {other}, 8(sp)\n"
                if store:
                    prologue += f"addi {other}, sp, 16\n"
                    value = other
                    epilogue = f"ld {other}, 8(sp)\n" + epilogue
                else:
                    # A load/address assignment changes SP. Keep the old save
                    # frame reachable until both borrowed registers are restored.
                    prologue += f"mv {other}, sp\n"
                    epilogue = f"ld {scratch}, 0({other})\nld {other}, 8({other})\n"

        operation = f"mv {value}, {scratch}\n" if address else f"{mnemonic} {value}, 0({scratch})\n"
        if address and reusable:
            operation = ""
        # LLVM MC defaults to the integer ISA. This directive affects only this
        # assembly transaction, and is needed only for an existing FP operation.
        isa = ('.attribute arch,"rv64ifd"\n' if mnemonic in {"fld", "fsd"} else
               '.attribute arch,"rv64if"\n' if mnemonic in {"flw", "fsw"} else "")
        return isa + prologue + self.arch._pcrel_address_snippet(scratch, target) + operation + epilogue

    def end_module(self, module, functions):
        print(
            f"[teapot] RV64 GP normalization: {self.normalized} references, "
            f"{self.reused} destination reuses, {self.spare} spare registers, "
            f"{self.spilled} stack-spilled sites",
            flush=True)
