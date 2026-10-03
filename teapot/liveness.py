"""DDisasm's live-register masks, as the rewrite uses them.

Teapot runs no liveness analysis of its own. It requires the masks DDisasm
writes (liveRegisterNames, liveRegisterSets, on x64 liveRegisterSetsHigh for the
vector pieces) under the flag rule this Teapot was built for, validates them,
and projects them onto registers for patch allocation. An instruction without
a mask, such as one a pass inserted, keeps every register live; so does a
block without an address.
"""
import copy
from typing import Dict, List, Mapping, Optional, Set

import gtirb
from gtirb_functions import Function
from gtirb_rewriting.assembly import Register
from gtirb_rewriting.patch import Constraints, InsertionContext

LIVE_REGISTER_NAMES_AUXDATA = "liveRegisterNames"
LIVE_REGISTER_SETS_AUXDATA = "liveRegisterSets"
LIVE_REGISTER_SETS_HIGH_AUXDATA = "liveRegisterSetsHigh"
LIVE_REGISTER_FLAG_RULE_AUXDATA = "liveRegisterFlagRule"
LIVE_REGISTER_NAMES_TYPE = "sequence<string>"
LIVE_REGISTER_SETS_TYPE = "mapping<Offset,uint64_t>"
# The rule the flags bit must follow: the flags one by one, none live into a
# return, and a direct call to a known function passing on what its entry
# reads. Lifts of older DDisasm versions say "call-boundary": every call killed
# the flags there, also where a callee reads its caller's flags (OpenSSL's
# __rsaz_512_mulx takes the carry its callers leave), so they are refused.
FLAG_RULE = "callee-entry"
OLD_FLAG_RULES = {
    "call-boundary": "an older DDisasm, whose masks kill every flag at a call, also where the callee reads them",
}

# The x64 vector pieces in the producer's names, in the order of the vector
# masks producer_vector_mask returns (teapot/arch/x64/checkpoint_state.py):
# the low 128 bits of each register, then the next 128 and the high 256, then
# the mask registers. The names designate non-overlapping pieces.
VECTOR_REGISTER_NAMES = (
    tuple(f"xmm{i}" for i in range(32)) +
    tuple(f"ymm{i}h" for i in range(32)) +
    tuple(f"zmm{i}h" for i in range(32)) +
    tuple(f"k{i}" for i in range(8))
)

REMEDY = ("relift the input with the supported DDisasm (the lin-toto/ddisasm fork the Dockerfile pins), "
          f"which writes liveRegisterNames, liveRegisterSets and liveRegisterFlagRule {FLAG_RULE!r}; "
          "tools/mask_audit.py checks a lift")


class NotEnoughFreeRegistersException(Exception):
    pass


class LivenessMetadataError(ValueError):
    """The lift's live-register masks cannot be used."""


class LiveRegisterManager:
    """Validated DDisasm masks, projected onto the ABI's registers per instruction."""

    analysis_source = "ddisasm"

    def __init__(self, module: gtirb.Module, abi, decoder=None, *, conservative_flags: bool = False):
        if decoder is None:
            from gtirb_live_register_analysis.utils import CachedGtirbInstructionDecoder
            decoder = CachedGtirbInstructionDecoder(module.isa)
        self.module, self.abi, self.decoder = module, abi, decoder
        self.conservative_flags = conservative_flags
        # result_cache[function][block] holds one register set per instruction.
        self.result_cache: Dict = {}
        self.discarded = 0
        self.checkpoint_vector_reasons = {}
        self.refresh(preserve_liveness=True)

    def refresh(self, *, preserve_liveness: bool = False):
        """Reload the masks after an IR edit and discard per-round results.

        Set preserve_liveness only for edits that keep the application's
        register dependencies and control flow, with migrated offsets, as
        Teapot's instrumentation rounds do. Otherwise the module's masks are
        dropped: every instruction becomes all-live, which is safe.
        """
        sets_aux = self.module.aux_data.get(LIVE_REGISTER_SETS_AUXDATA)
        if (not preserve_liveness and sets_aux is not None and
                isinstance(sets_aux.data, Mapping) and sets_aux.data):
            sets_aux.data = {}
            high = self.module.aux_data.get(LIVE_REGISTER_SETS_HIGH_AUXDATA)
            if high is not None:
                high.data = {}
        self.result_cache.clear()
        if hasattr(self.decoder, "cache"):
            self.decoder.cache.clear()
        self._load()

    def _fail(self, reason):
        raise LivenessMetadataError(f"module {self.module.name!r}: {reason}; {REMEDY}")

    def _load(self):
        aux = self.module.aux_data
        names_aux, sets_aux = aux.get(LIVE_REGISTER_NAMES_AUXDATA), aux.get(LIVE_REGISTER_SETS_AUXDATA)
        if names_aux is None or sets_aux is None:
            self._fail("the lift has no DDisasm live-register masks")
        rule = aux.get(LIVE_REGISTER_FLAG_RULE_AUXDATA)
        if rule is None or rule.type_name != "string":
            self._fail(f"the masks name no {LIVE_REGISTER_FLAG_RULE_AUXDATA} (an older DDisasm)")
        if rule.data != FLAG_RULE:
            why = OLD_FLAG_RULES.get(rule.data, "a rule this Teapot does not know")
            self._fail(f"the masks follow the flag rule {rule.data!r}, {why}, not {FLAG_RULE!r}")
        if names_aux.type_name != LIVE_REGISTER_NAMES_TYPE:
            self._fail(f"{LIVE_REGISTER_NAMES_AUXDATA} has type {names_aux.type_name}")
        if sets_aux.type_name != LIVE_REGISTER_SETS_TYPE or not isinstance(sets_aux.data, Mapping):
            self._fail(f"{LIVE_REGISTER_SETS_AUXDATA} has type {sets_aux.type_name}")

        names = list(names_aux.data)
        if not names or len(names) > 128 or any(not isinstance(name, str) or not name for name in names):
            self._fail("the register-name table must contain 1-128 non-empty names")
        wide_x64 = self.module.isa == gtirb.Module.ISA.X64 and len(names) > 64
        try:
            # The allocator works on physical registers; the vector pieces keep
            # their own names for the checkpoint masks.
            registers = [self.abi.get_register(name[:-1] if wide_x64 and name in VECTOR_REGISTER_NAMES and
                                               name.endswith("h") else name)
                         for name in names]
        except (KeyError, ValueError) as error:
            self._fail(f"the register-name table names a register this ABI does not have ({error})")
        scalar = [register for name, register in zip(names, registers)
                  if not (wide_x64 and name in VECTOR_REGISTER_NAMES)]
        if len(set(names)) != len(names) or len(set(scalar)) != len(scalar):
            self._fail("the register-name table contains aliases of the same register")
        if not set(self.abi._scratch_registers()).issubset(registers):
            self._fail("the register-name table omits allocatable scratch registers")
        flag_register = self.abi.flag_register()
        if flag_register is not None and flag_register not in registers:
            self._fail("the register-name table omits the condition flags")

        # An entry outside its block, or with bits beyond the table, is dropped
        # (that instruction becomes all-live); the pipeline reports the count.
        valid_bits = (1 << min(64, len(registers))) - 1
        invalid = [offset for offset, mask in sets_aux.data.items()
                   if not (isinstance(offset, gtirb.Offset) and isinstance(offset.element_id, gtirb.CodeBlock) and
                           offset.element_id.module is self.module and isinstance(offset.displacement, int) and
                           0 <= offset.displacement < offset.element_id.size and isinstance(mask, int) and
                           0 <= mask and not mask & ~valid_bits)]
        self.discarded = len(invalid)
        if invalid:
            sets_aux.data = {offset: mask for offset, mask in sets_aux.data.items() if offset not in set(invalid)}
        # The AuxData's own mapping, not a copy: the rewriter migrates its
        # offsets in place as it inserts code.
        self.registers, self.masks = registers, sets_aux.data

        self.vector_bit_indices, self.high_masks = None, {}
        if self.module.isa == gtirb.Module.ISA.X64 and set(VECTOR_REGISTER_NAMES).issubset(names):
            self.vector_bit_indices = tuple(names.index(name) for name in VECTOR_REGISTER_NAMES)
            high = aux.get(LIVE_REGISTER_SETS_HIGH_AUXDATA)
            if high is not None:
                if high.type_name == LIVE_REGISTER_SETS_TYPE and isinstance(high.data, Mapping):
                    self.high_masks = {offset: mask for offset, mask in high.data.items()
                                       if offset in self.masks and isinstance(mask, int) and
                                       0 <= mask < (1 << (len(names) - 64))}
                    high.data = self.high_masks
                else:
                    aux.pop(LIVE_REGISTER_SETS_HIGH_AUXDATA)

    def analyze(self, function: Function):
        """Project the masks of the function's instructions; a missing mask is all-live."""
        if function.uuid in self.result_cache:
            return
        all_registers = set(self.abi.all_registers())
        flag_register = self.abi.flag_register()
        wide = len(self.registers) > 64
        function_registers = {}
        for block in function.get_all_blocks():
            block_registers = []
            for instruction in self.decoder.get_instructions(block):
                mask = (self.masks.get(gtirb.Offset(block, instruction.address - block.address))
                        if block.address is not None else None)
                if mask is None:
                    block_registers.append(set(all_registers))
                    continue
                if wide:
                    # A missing high word keeps the physical vector registers
                    # live; it does not spoil the valid low GPR bits.
                    offset = gtirb.Offset(block, instruction.address - block.address)
                    mask |= self.high_masks.get(offset, (1 << 64) - 1) << 64
                live = {register for index, register in enumerate(self.registers) if mask & (1 << index)}
                if self.conservative_flags and flag_register is not None:
                    live.add(flag_register)
                block_registers.append(live)
            function_registers[block.uuid] = block_registers
        self.result_cache[function.uuid] = function_registers

    def producer_vector_mask(self, block: gtirb.CodeBlock, displacement: int) -> Optional[int]:
        """DDisasm's x64 vector pieces at an original instruction, or None (unknown, so full)."""
        if self.vector_bit_indices is None:
            return None
        offset = gtirb.Offset(block, displacement)
        low, high = self.masks.get(offset), self.high_masks.get(offset)
        if low is None or high is None:
            return None
        mask = low | (high << 64)
        return sum(1 << bit for bit, index in enumerate(self.vector_bit_indices) if mask & (1 << index))

    def live_registers(self, function: Function, block: gtirb.CodeBlock, instruction_idx: int) -> Set[Register]:
        assert function.uuid in self.result_cache, "live registers of the function have not been projected"
        block_registers = self.result_cache[function.uuid].get(block.uuid)
        if block_registers is None or not 0 <= instruction_idx < len(block_registers):
            return set(self.abi.all_registers())
        return block_registers[instruction_idx]

    def add_live_registers(self, function: Function, block: gtirb.CodeBlock, instruction_idx: int,
                           registers: Set[Register]):
        self.live_registers(function, block, instruction_idx).update(registers)

    def free_registers(self, function: Function, block: gtirb.CodeBlock, instruction_idx: int) -> Set[Register]:
        return set(self.abi._scratch_registers()).difference(self.live_registers(function, block, instruction_idx))

    def _free_registers_ordered(self, function, block, instruction_idx) -> List[Register]:
        live = self.live_registers(function, block, instruction_idx)
        return [register for register in self.abi._scratch_registers() if register not in live]

    def allocate_registers(self, function: Function, block: gtirb.CodeBlock, instruction_idx: int,
                           allow_fallback: bool = True):
        """Give a patch the free scratch registers at the instruction.

        The rewriter spills and restores the scratch registers that remain;
        with allow_fallback False, too few free registers is an error instead.
        A patch that clobbers the flags need not save them where they are dead.
        """

        def patch_func_decorator(f):
            assert hasattr(f, "constraints"), "the patch function has no constraints"
            constraints: Constraints = copy.deepcopy(f.constraints)
            free = self._free_registers_ordered(function, block, instruction_idx)
            assigned = free[:min(len(free), constraints.scratch_registers)]
            constraints.scratch_registers -= len(assigned)
            constraints.reads_registers.update(register.name for register in assigned)
            if constraints.scratch_registers > 0 and not allow_fallback:
                raise NotEnoughFreeRegistersException()
            if (constraints.clobbers_flags and
                    self.abi.flag_register() not in self.live_registers(function, block, instruction_idx)):
                constraints.clobbers_flags = False

            def func_wrapper(ctx: InsertionContext):
                ctx.scratch_registers += assigned
                return f(ctx)

            func_wrapper.constraints = constraints
            return func_wrapper

        return patch_func_decorator
