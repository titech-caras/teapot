import gtirb
from gtirb_live_register_analysis import LiveRegisterManager
from gtirb_functions import Function

from teapot.datacls.copied_section_mapping import CopiedSectionMapping


CALL_EDGE_TYPES = {gtirb.EdgeType.Call, gtirb.EdgeType.Return}


class LiveRegisterManagerWrapper(LiveRegisterManager):
    def __init__(self, *args, text_transient_mapping: CopiedSectionMapping):
        super().__init__(*args)
        self.text_transient_mapping = text_transient_mapping

    def analyze(self, function: Function):
        if function.uuid in self.result_cache:
            return

        super().analyze(function)
        self._analyze_missing_blocks_from_successors(function)
        self._analyze_terminal_call_blocks(function)
        self._analyze_remaining_blocks_locally(function)

        if function.uuid in self.text_transient_mapping.function_uuids_map:
            copied_uuid = self.text_transient_mapping.function_uuids_map[function.uuid]

            self.result_cache[copied_uuid] = {}
            for block_uuid, regs in self.result_cache[function.uuid].items():
                try:
                    copied_block_uuid = self.text_transient_mapping.code_blocks_map[block_uuid].uuid
                    self.result_cache[copied_uuid][copied_block_uuid] = regs
                except KeyError:
                    pass

    def _analyze_terminal_call_blocks(self, function: Function):
        for block in function.get_all_blocks():
            if block.uuid in self.result_cache[function.uuid]:
                continue
            if not self._is_terminal_call_block(block):
                continue

            instructions = list(self.analyzer.decoder.get_instructions(block))
            self.result_cache[function.uuid][block.uuid] = self._compute_local_live_registers(instructions)

    def _analyze_missing_blocks_from_successors(self, function: Function):
        changed = True
        while changed:
            changed = False
            for block in function.get_all_blocks():
                if block.uuid in self.result_cache[function.uuid]:
                    continue

                instructions = list(self.analyzer.decoder.get_instructions(block))
                if not instructions:
                    self.result_cache[function.uuid][block.uuid] = []
                    changed = True
                    continue

                successor_live_registers = []
                has_unanalyzed_successor = False
                for edge in block.outgoing_edges:
                    if edge.label.type in CALL_EDGE_TYPES or not isinstance(edge.target, gtirb.CodeBlock):
                        continue

                    target_registers = self.result_cache[function.uuid].get(edge.target.uuid)
                    if target_registers is None:
                        has_unanalyzed_successor = True
                        continue
                    if target_registers:
                        successor_live_registers.append(target_registers[0])

                if not successor_live_registers and has_unanalyzed_successor:
                    continue

                out_registers = set().union(*successor_live_registers) if successor_live_registers else set()
                self.result_cache[function.uuid][block.uuid] = self._compute_local_live_registers(
                    instructions, out_registers)
                changed = True

    def _analyze_remaining_blocks_locally(self, function: Function):
        all_registers = set(self.abi.all_registers())
        for block in function.get_all_blocks():
            if block.uuid in self.result_cache[function.uuid]:
                continue

            instructions = list(self.analyzer.decoder.get_instructions(block))
            self.result_cache[function.uuid][block.uuid] = self._compute_local_live_registers(
                instructions, all_registers)

    @staticmethod
    def _is_terminal_call_block(block: gtirb.CodeBlock) -> bool:
        has_call_edge = False
        for edge in block.outgoing_edges:
            if edge.label.type == gtirb.EdgeType.Call:
                has_call_edge = True
                continue
            if isinstance(edge.target, gtirb.CodeBlock) and edge.label.type not in CALL_EDGE_TYPES:
                return False
        return has_call_edge

    def _compute_local_live_registers(self, instructions, out_registers=None):
        live_registers = [set() for _ in instructions]
        out_registers = set() if out_registers is None else set(out_registers)
        for idx in range(len(instructions) - 1, -1, -1):
            instruction = instructions[idx]
            gen_registers = self.analyzer._instruction_regs_read(instruction)
            kill_registers = self.analyzer._instruction_regs_write(instruction).difference(gen_registers)
            live_registers[idx] = gen_registers.union(out_registers.difference(kill_registers))
            out_registers = live_registers[idx]
        return live_registers
