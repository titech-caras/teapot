"""Exact-window selection, printer stability and native guard semantics."""
from pathlib import Path
import os
import platform
import shutil
import struct
import subprocess
import tempfile
import unittest
import uuid
from unittest.mock import patch

import gtirb
from gtirb_rewriting.decoder import GtirbInstructionDecoder
from teapot.fault_x64 import Address, decoder, scalar_access, select_window, guard_template, mark_input
from teapot.preprocess.fault_windows import add_fault_windows, wide_access, _splice_batch
from teapot.preprocess.copy_section import set_elf_section_properties, create_section_bounds
from teapot.fault_window_validation import validate_windows, require_isolated_copy_pages


class FaultWindowSelectionTests(unittest.TestCase):
    def instructions(self, text): return tuple(decoder().disasm(bytes.fromhex(text), 0x1000))

    def test_complete_window_and_target_barriers(self):
        instructions = self.instructions("488b074889c3c3")
        self.assertEqual(sum(i.size for i in select_window(instructions, 0)), 6)
        for target in (0x1001, 0x1003, 0x1004):
            self.assertFalse(select_window(instructions, 0, {target}))
        self.assertFalse(select_window(instructions[:1], 0))
        self.assertFalse(select_window(self.instructions("488b07e900000000"), 0))
        self.assertFalse(select_window(instructions, 0, {0x1003, 0x1004, 0x1005}))

    def test_scalar_eligibility_and_true_address(self):
        for text in ("488b07", "488b448608", "67488b448608", "4b8b449e7f"):
            instruction = self.instructions(text)[0]
            address = scalar_access(instruction)
            self.assertIsNotNone(address, text)
            lea = tuple(decoder().disasm(address.lea(), 0))[0]
            self.assertEqual(lea.mnemonic, "lea")
            memory = lea.operands[1].mem
            from capstone import x86_const as x
            original = next(op.mem for op in instruction.operands if op.type == x.X86_OP_MEM)
            self.assertEqual((memory.base,memory.index,memory.scale,memory.disp),
                             (original.base,original.index,original.scale,original.disp))
        for text in ("488b0424", "488b4500", "488b0500000000", "648b00", "f048830001",
                     "f3a4", "0f1007", "488707", "480fab07", "488b04e7"):
            self.assertIsNone(scalar_access(self.instructions(text)[0]), text)

    def test_fallback_is_branch_sized_and_ea_identical(self):
        for text in ("488b07", "8b07", "488b4701", "4b8b041e", "67488b07", "803b05", "668b07"):
            insn = self.instructions(text)[0]
            code = wide_access(insn)
            self.assertTrue(code and 5 <= len(code) <= 15, text)
            self.assertEqual(scalar_access(self.instructions(code.hex())[0]), scalar_access(insn))
        self.assertIsNone(wide_access(self.instructions("488b0424")[0]))

    def test_fallback_refuses_changed_immediate_opcode_and_operand_size(self):
        original = self.instructions("803b05")[0]  # cmp byte [rbx], 5
        for damaged in ("80bb0000000006", "f6bb0000000005", "6681bb000000000500"):
            changed = self.instructions(damaged)[0]
            self.assertEqual(scalar_access(original), scalar_access(changed))
            with self.subTest(damaged=damaged), patch("teapot.preprocess.fault_windows.decoder") as mocked:
                mocked.return_value.disasm.return_value = iter((changed,))
                with self.assertRaisesRegex(ValueError, "instruction semantics"):
                    wide_access(original)

    def test_copy_pages_reject_other_allocated_sections_and_partial_end(self):
        from types import SimpleNamespace
        class Section(dict):
            def __init__(self, name, address, size, flags=6):
                super().__init__(sh_addr=address, sh_size=size, sh_flags=flags)
                self.name = name
        own = Section(".teapot_transient", 0x2000, 0x1000)
        for other in (Section(".plt", 0x2ff0, 32), Section(".rodata", 0x2000, 16, 2),
                      Section(".bss", 0x2f00, 16, 3)):
            with self.subTest(section=other.name), self.assertRaisesRegex(ValueError, "shares a patchable page"):
                require_isolated_copy_pages(SimpleNamespace(iter_sections=lambda: iter((own,other))),0x2000,0x3000)
        outside = Section(".plt", 0x3000, 32)
        nonalloc = Section(".debug_info", 0x2000, 16, 0)
        require_isolated_copy_pages(SimpleNamespace(iter_sections=lambda: iter((own,outside,nonalloc))),0x2000,0x3000)
        partial = Section(".teapot_transient", 0x2000, 0xff0)
        with self.assertRaisesRegex(ValueError, "not page-isolated"):
            require_isolated_copy_pages(SimpleNamespace(iter_sections=lambda: iter((partial,))),0x2000,0x2ff0)

    def test_rip_and_flag_reading_tail_is_movable_but_call_is_not(self):
        for text in ("488b074883d001", "488b07488d1500000000", "488b0784c0", "488b079090"):
            self.assertTrue(select_window(self.instructions(text), 0), text)
        for text in ("488b07ffd0", "488b075f", "488b079f", "488b07f390",
                     "488b078ed8", "488b0767488d1500000000"):
            self.assertFalse(select_window(self.instructions(text), 0), text)


class FaultWindowBatchEditTests(unittest.TestCase):
    def make_interval(self):
        module = gtirb.Module(name="batch", isa=gtirb.Module.ISA.X64)
        gtirb.IR(modules=[module])
        section = gtirb.Section(name=".text", module=module)
        interval = gtirb.ByteInterval(address=0x1000, contents=b"abcdefghijklmnop", section=section)
        blocks = [gtirb.DataBlock(offset=offset, size=size, byte_interval=interval)
                  for offset, size in ((0,2), (2,2), (4,6), (10,4), (14,2))]
        island = gtirb.CodeBlock(offset=10, size=0, byte_interval=interval)
        end = gtirb.CodeBlock(offset=16, size=0, byte_interval=interval)
        start_symbol = gtirb.Symbol(name="start", payload=blocks[1], module=module)
        end_symbol = gtirb.Symbol(name="end", payload=blocks[1], at_end=True, module=module)
        expressions = {offset: gtirb.SymAddrConst(offset, start_symbol) for offset in (4,10)}
        interval.symbolic_expressions.update(expressions)
        module.aux_data["symbolicExpressionSizes"] = gtirb.AuxData(
            {gtirb.Offset(interval, offset):4 for offset in expressions}, "mapping<Offset,uint64_t>")
        return module, interval, blocks, island, end, start_symbol, end_symbol, expressions

    def test_batch_moves_bytes_nodes_symbols_and_relocations_once(self):
        module, interval, blocks, island, end, start_symbol, end_symbol, expressions = self.make_interval()
        positions = _splice_batch(module, interval, [(14,2,b"uvwxyz"), (10,0,b"QRST"), (2,2,b"ABC")],
                                  left={island})
        self.assertEqual(interval.contents, b"abABCefghijQRSTklmnuvwxyz")
        self.assertEqual(interval.size,25)
        self.assertEqual(positions,{2:2,10:11,14:19})
        self.assertEqual([(block.offset,block.size) for block in blocks],[(0,2),(2,3),(5,6),(15,4),(19,6)])
        self.assertEqual((island.offset,end.offset),(11,25))
        self.assertIs(start_symbol.referent,blocks[1]); self.assertIs(end_symbol.referent,blocks[1])
        self.assertEqual((start_symbol.referent.address, end_symbol.referent.address + end_symbol.referent.size),
                         (0x1002,0x1005))
        self.assertEqual(dict(interval.symbolic_expressions),{5:expressions[4],15:expressions[10]})
        self.assertEqual(module.aux_data["symbolicExpressionSizes"].data,
                         {gtirb.Offset(interval,5):4,gtirb.Offset(interval,15):4})

    def test_invalid_batch_is_refused_before_any_mutation(self):
        for edits in ([(1,0,b"x")], [(2,1,b"x")], [(3,1,b"x")], [(4,1,b"x")],
                      [(2,2,b"X"),(3,1,b"Y")], [(16,0,b"X"),(16,0,b"Y")], [(17,0,b"X")]):
            with self.subTest(edits=edits):
                module, interval, blocks, island, end, _, _, expressions = self.make_interval()
                with self.assertRaises(ValueError): _splice_batch(module,interval,edits,left={island})
                self.assertEqual(interval.contents,b"abcdefghijklmnop"); self.assertEqual(interval.size,16)
                self.assertEqual([(block.offset,block.size) for block in blocks],[(0,2),(2,2),(4,6),(10,4),(14,2)])
                self.assertEqual(dict(interval.symbolic_expressions),expressions)

    def test_many_islands_keep_left_anchors_and_following_words_consistent(self):
        module = gtirb.Module(name="islands", isa=gtirb.Module.ISA.X64); gtirb.IR(modules=[module])
        interval = gtirb.ByteInterval(contents=b"ab"*512, section=gtirb.Section(name=".text", module=module))
        anchors = [gtirb.CodeBlock(offset=2*i,size=0,byte_interval=interval) for i in range(512)]
        blocks = [gtirb.DataBlock(offset=2*i,size=2,byte_interval=interval) for i in range(512)]
        positions = _splice_batch(module,interval,[(2*i,0,b"XYZ") for i in reversed(range(512))],left=set(anchors))
        self.assertEqual(interval.contents,b"XYZab"*512)
        self.assertEqual([anchor.offset for anchor in anchors],[5*i for i in range(512)])
        self.assertEqual([block.offset for block in blocks],[5*i+3 for i in range(512)])
        self.assertEqual(positions,{2*i:5*i for i in range(512)})


def emit_template(code, fields, targets, *, name):
    lines = [name + ":"]
    cursor = 0
    for offset, key, addend in fields:
        if offset > cursor: lines.append(".byte " + ",".join(str(b) for b in code[cursor:offset]))
        lines.append(f".long {targets[key]}+({addend})-.")
        cursor = offset + 4
    if cursor < len(code): lines.append(".byte " + ",".join(str(b) for b in code[cursor:]))
    return "\n".join(lines)


def preserve_evidence(root, destination):
    """Retain container-made evidence readable by the independent reviewer."""
    shutil.copytree(root, destination)
    for path in (destination, *destination.rglob("*")):
        path.chmod(path.stat().st_mode | (0o055 if path.is_dir() else 0o044))


@unittest.skipUnless(platform.machine() == "x86_64" and shutil.which("gcc"), "native x64 compiler")
class FaultGuardNativeTests(unittest.TestCase):
    def test_guard_preserves_registers_flags_df_and_faults_without_accessing_memory(self):
        # Exercise the permitted tail vocabulary, not just a MOV whose flags
        # are inert. Each case sees all six arithmetic flags plus DF.
        for text, rip in (("488b074889c3", None), ("488b074883d301", None),
                          ("488b074885c0", None), ("488b0783c001", None),
                          ("488b079090", None), ("488b07488b1d00000000", 6)):
            with self.subTest(window=text):
                self.check_window(bytes.fromhex(text), rip)

    def check_window(self, window, rip):
        code, fields, copy = guard_template(Address(7), window)
        original_fields = () if rip is None else ((rip, "ripdata", -4),)
        if rip is not None:
            fields = tuple(sorted((*fields, (copy + rip, "ripdata", -4))))
        assembly = """
.text
.global probe
.type probe,@function
probe:
    push %rbx
    push %rbp
    push %r12
    push %r13
    push %r14
    push %r15
    mov %rdi,%r10
    mov %rsi,%rdi
    push %rdx
    popfq
    mov $0x1234,%rax
    mov $0x5678,%r11
    mov $0x9876,%rbx
    call *%r10
    pushfq
    pop %r8
    cld
    mov %rax,0(%rcx)
    mov %rbx,8(%rcx)
    mov %r11,16(%rcx)
    mov %rdi,24(%rcx)
    mov %rsi,32(%rcx)
    mov %r8,40(%rcx)
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbp
    pop %rbx
    ret
.global original
""" + emit_template(window, original_fields, {"ripdata":"rip_value"}, name="original") + """
continuation:
    ret
failed:
    mov $-1,%rax
    ret
.global checked
""" + emit_template(code, fields, {"spill":"private_spill","low":"low_bound", "return":"continuation",
                                  "rollback":"failed", "ripdata":"rip_value"}, name="checked") + """
.data
.balign 8
low_bound: .quad 4096
rip_value: .quad 0x1456abcc8910eeff
.bss
.balign 8
private_spill: .zero 24
.section .note.GNU-stack,"",@progbits
"""
        c = """
#include <stdint.h>
#include <string.h>
extern void probe(void *, uintptr_t, uint64_t, uint64_t *);
extern char original[], checked[];
int main(void) {
    uint64_t value = 0xabcdef0123456789ULL, a[6], b[6];
    unsigned positions[] = {0,2,4,6,7,11,10};
    for (unsigned flags = 0; flags < 128; ++flags) {
        uint64_t status = 2;
        for (unsigned bit = 0; bit < 7; ++bit) if (flags & (1u << bit)) status |= 1ULL << positions[bit];
        probe(original, (uintptr_t)&value, status, a);
        probe(checked, (uintptr_t)&value, status, b);
        if (memcmp(a,b,sizeof(a))) return 1;
    }
    uintptr_t invalid[] = {0,1,4095,1ULL<<56,~(uintptr_t)0};
    for (unsigned i = 0; i < sizeof(invalid)/sizeof(*invalid); ++i) {
        probe(checked, invalid[i], 2, b);
        if (b[0] != ~(uint64_t)0) return 2;
    }
    return 0;
}
"""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root/"probe.S").write_text(assembly); (root/"probe.c").write_text(c)
            result = subprocess.run(["gcc","-O2","-no-pie","probe.c","probe.S","-o","probe"],
                                    cwd=root, text=True, capture_output=True, timeout=30)
            self.assertEqual(result.returncode,0,result.stderr)
            result = subprocess.run([str(root/"probe")],cwd=root,text=True,capture_output=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)


@unittest.skipUnless(shutil.which("gtirb-pprinter") and shutil.which("gcc"), "requires printer/linker")
class FaultWindowEmitterTests(unittest.TestCase):
    def make_module(self, code, *, trailing_helper=False):
        module = gtirb.Module(name="window", isa=gtirb.Module.ISA.X64, file_format=gtirb.Module.FileFormat.ELF,
                              byte_order=gtirb.Module.ByteOrder.Little)
        gtirb.IR(modules=[module])
        section = gtirb.Section(name=".teapot_transient", module=module,
            flags={gtirb.Section.Flag.Readable, gtirb.Section.Flag.Executable, gtirb.Section.Flag.Loaded,
                   gtirb.Section.Flag.Initialized})
        set_elf_section_properties(section,1,6)
        interval = gtirb.ByteInterval(address=0x1000,contents=code,section=section)
        block = gtirb.CodeBlock(size=len(code),byte_interval=interval)
        symbol = gtirb.Symbol(name="window_test",payload=block,module=module)
        function = uuid.uuid4()
        module.aux_data["functionEntries"] = gtirb.AuxData({function:{block}},"mapping<UUID,set<UUID>>")
        module.aux_data["functionBlocks"] = gtirb.AuxData({function:{block}},"mapping<UUID,set<UUID>>")
        module.aux_data["functionNames"] = gtirb.AuxData({function:symbol},"mapping<UUID,UUID>")
        module.aux_data["elfSymbolInfo"] = gtirb.AuxData({symbol:(len(code),"FUNC","GLOBAL","DEFAULT",0)},
            "mapping<UUID,tuple<uint64_t,string,string,string,uint64_t>>")
        module.entry_point = block
        mark_input(section,GtirbInstructionDecoder(module.isa))
        if trailing_helper:
            interval.contents += bytes.fromhex("909090")
            interval.size += 3
            helper = gtirb.CodeBlock(size=3,offset=len(code),byte_interval=interval)
            module.aux_data["functionBlocks"].data[function].add(helper)
        return module,section,create_section_bounds(section,"copy")

    def test_raw_window_survives_printing_and_final_validation(self):
        from elftools.elf.elffile import ELFFile
        relaxing_branch = bytes.fromhex("488b074889c10f8500000000c3")
        for code,helper,trampoline in ((bytes.fromhex("488b074889c1c3"),False,False),
                                      (bytes.fromhex("488b07c3"),False,False),
                                      (bytes.fromhex("488b074889c1c3"),True,False),
                                      (bytes.fromhex("488b074889c1c3"),False,True),
                                      (relaxing_branch,False,False)):
            with self.subTest(code=code.hex(),trailing_helper=helper,trampoline=trampoline), tempfile.TemporaryDirectory() as directory:
                module,section,bounds = self.make_module(code,trailing_helper=helper)
                if code == relaxing_branch:
                    # A six-byte near JNE prints/assembles as a two-byte short
                    # branch. The raw adaptive window is unaffected, but the
                    # computed IR tail padding is now four bytes too short.
                    interval = next(iter(section.byte_intervals))
                    block = next(b for b in interval.blocks if isinstance(b,gtirb.CodeBlock) and b.size)
                    block.size -= 1
                    target = gtirb.CodeBlock(size=1,offset=len(code)-1,byte_interval=interval)
                    symbol = gtirb.Symbol(name="relaxed_tail",payload=target,module=module)
                    next(iter(module.aux_data["functionBlocks"].data.values())).add(target)
                    interval.symbolic_expressions[8] = gtirb.SymAddrConst(0,symbol)
                    module.aux_data["symbolicExpressionSizes"] = gtirb.AuxData(
                        {gtirb.Offset(interval,8):4},"mapping<Offset,uint64_t>")
                add_fault_windows(module,section,bounds)
                interval = next(iter(section.byte_intervals))
                self.assertEqual(interval.size % 4096, 0)
                self.assertEqual(bounds[1].referent.offset, interval.size)
                tail = next(b for b in interval.blocks if isinstance(b,gtirb.DataBlock) and
                            b.size > 0 and b.offset + b.size == interval.size)
                self.assertEqual(interval.contents[tail.offset:],b"\xcc" * tail.size)
                root = Path(directory); module.ir.save_protobuf(root/"in.gtirb")
                (root/"runtime.S").write_text("""
.text
.global restore_checkpoint_SIGSEGV
restore_checkpoint_SIGSEGV: ret
.section teapot_protected_bss,"aw",@nobits
.balign 8
.global teapot_fault_low_bound
teapot_fault_low_bound: .zero 8
.section .note.GNU-stack,"",@progbits
""")
                if trampoline:
                    with (root/"runtime.S").open("a") as stream:
                        stream.write('.section .teapot_trampolines,"ax",@progbits\njmp window_test+1\n')
                for command in (["gtirb-pprinter","--ir","in.gtirb","--asm","fixed.S","--shared","no"],
                                ["gcc","-nostdlib","-no-pie","fixed.S","runtime.S","-Wl,-e,window_test",
                                 "-Wl,-z,separate-code","-o","linked"]):
                    result = subprocess.run(command,cwd=root,text=True,capture_output=True,timeout=30)
                    self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                with (root/"linked").open("rb") as stream:
                    elf = ELFFile(stream); table = elf.get_section_by_name("teapot_fault_sites")
                    copy_section = elf.get_section_by_name(".teapot_transient")
                    self.assertEqual((copy_section["sh_addr"] + copy_section["sh_size"]) % 4096, 0,
                                     "assembler relaxation left a partial patch page")
                    if trampoline:
                        with self.assertRaisesRegex(ValueError,"incoming direct transfer inside"):
                            validate_windows(elf,table["sh_addr"])
                        continue
                    self.assertEqual(validate_windows(elf,table["sh_addr"])["count"],1)
                    # A final ELF, not just the IR, must reject a shared page.
                    # Corrupt only an allocated section's address, like the
                    # real unpadded last-page .plt finding.
                    from io import BytesIO
                    text_index = next(i for i,s in enumerate(elf.iter_sections()) if s.name == ".text")
                    end = elf.get_section_by_name(".teapot_transient")["sh_addr"] + interval.size
                    damaged = bytearray((root/"linked").read_bytes())
                    struct.pack_into("<Q",damaged,elf["e_shoff"] + text_index * elf["e_shentsize"] + 16,end-8)
                    with self.assertRaisesRegex(ValueError,"allocated section shares a patchable page"):
                        validate_windows(ELFFile(BytesIO(damaged)),table["sh_addr"])

    def test_rip_relative_copy_survives_printing_and_corruption_is_refused(self):
        from elftools.elf.elffile import ELFFile
        from io import BytesIO
        module,section,bounds = self.make_module(bytes.fromhex("488b07488b1d00000000c3"))
        data = gtirb.Section(name=".data",module=module,flags={gtirb.Section.Flag.Readable,
            gtirb.Section.Flag.Writable,gtirb.Section.Flag.Loaded,gtirb.Section.Flag.Initialized})
        set_elf_section_properties(data,1,3)
        interval = gtirb.ByteInterval(address=0x2000,contents=bytes(8),section=data)
        block = gtirb.DataBlock(size=8,byte_interval=interval)
        target = gtirb.Symbol(name="rip_data",payload=block,module=module)
        source = next(iter(section.byte_intervals))
        source.symbolic_expressions[6] = gtirb.SymAddrConst(0,target)
        module.aux_data["symbolicExpressionSizes"] = gtirb.AuxData({gtirb.Offset(source,6):4},
            "mapping<Offset,uint64_t>")
        add_fault_windows(module,section,bounds)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); module.ir.save_protobuf(root/"in.gtirb")
            (root/"runtime.S").write_text("""
.text
.global restore_checkpoint_SIGSEGV
restore_checkpoint_SIGSEGV: ret
.section teapot_protected_bss,"aw",@nobits
.balign 8
.global teapot_fault_low_bound
teapot_fault_low_bound: .zero 8
.section .note.GNU-stack,"",@progbits
""")
            for command in (["gtirb-pprinter","--ir","in.gtirb","--asm","fixed.S","--shared","no"],
                            ["gcc","-nostdlib","-no-pie","fixed.S","runtime.S","-Wl,-e,window_test",
                             "-Wl,-z,separate-code","-o","linked"]):
                result=subprocess.run(command,cwd=root,text=True,capture_output=True,timeout=30)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            contents=(root/"linked").read_bytes()
            elf=ELFFile(BytesIO(contents)); table=elf.get_section_by_name("teapot_fault_sites")
            verified=validate_windows(elf,table["sh_addr"])
            self.assertEqual(verified["count"],1)
            pc,stub,copy,length=verified["entries"][0]
            transient=elf.get_section_by_name(".teapot_transient")
            # Each mutation must fail final-link validation: wrong EA, wrong
            # copied RIP target, clobbered save template and metadata length.
            offsets=(int(transient["sh_offset"])+pc-int(transient["sh_addr"])+2,
                     int(transient["sh_offset"])+copy-int(transient["sh_addr"])+6,
                     int(transient["sh_offset"])+stub-int(transient["sh_addr"]),
                     int(table["sh_offset"])+112+12)
            for offset in offsets:
                damaged=bytearray(contents); damaged[offset]^=1
                with self.subTest(offset=offset), self.assertRaises(ValueError):
                    validate_windows(ELFFile(BytesIO(damaged)),table["sh_addr"])

    def test_native_publication_and_permission_failures(self):
        self.check_native_publication(300)

    def test_native_publication_on_copy_last_page(self):
        self.check_native_publication(1, leading=3000)

    def check_native_publication(self, count, leading=0):
        from elftools.elf.elffile import ELFFile
        runtime = Path(os.environ.get("TEAPOT_RUNTIME_SOURCE", str(Path(__file__).resolve().parents[1]/"libcheckpoint")))
        if not (runtime/"src/fault_sites.c").is_file(): self.skipTest("requires matching runtime sources")
        # More than the bounded ring's 256 entries: exercise its exceptional
        # scan fallback without making the ordinary empty path scan any site.
        module,section,bounds = self.make_module(b"\x90" * leading + bytes.fromhex("488b074889c1") * count + b"\xc3")
        add_fault_windows(module,section,bounds)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); module.ir.save_protobuf(root/"in.gtirb")
            result = subprocess.run(["gtirb-pprinter","--ir","in.gtirb","--asm","fixed.S","--shared","no"],
                                    cwd=root,text=True,capture_output=True,timeout=30)
            self.assertEqual(result.returncode,0,result.stderr)
            (root/"check.c").write_text(r'''
#define _GNU_SOURCE
#include "fault_sites.h"
#include "runtime_contract.h"
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
extern const struct teapot_fault_site_table __start_teapot_fault_sites;
extern uint64_t window_test(const uint64_t *);
uintptr_t restore_checkpoint_SIGSEGV(void) { return UINTPTR_MAX; }
static int failure, active, rx_failures, masked_addresses;
bool __real_teapot_fault_x64_can_publish_addresses(void);
bool __wrap_teapot_fault_x64_can_publish_addresses(void) {
    return !masked_addresses && __real_teapot_fault_x64_can_publish_addresses();
}
long __real_teapot_fault_x64_mprotect(void *, size_t, int);
long __wrap_teapot_fault_x64_mprotect(void *p, size_t n, int prot) {
    if (active && ((failure == 1 && prot == (PROT_READ|PROT_WRITE)) ||
                  (failure == 2 && prot == (PROT_READ|PROT_EXEC) && rx_failures++ == 0) ||
                  (failure == 3 && prot == (PROT_READ|PROT_EXEC)))) { errno = EACCES; return -1; }
    return __real_teapot_fault_x64_mprotect(p,n,prot);
}
int main(int argc, char **argv) {
    assert(argc == 2);
    if (!strcmp(argv[1],"off")) setenv("TEAPOT_FAULT_ADAPTATION","0",1);
    if (!strcmp(argv[1],"masked")) masked_addresses=1;
    if (!strcmp(argv[1],"bad-end")) {
        uintptr_t page=(uintptr_t)&__start_teapot_fault_sites & ~(uintptr_t)4095;
        assert(!mprotect((void *)page,4096,PROT_READ|PROT_WRITE));
        struct teapot_fault_site_table *damaged=(void *)&__start_teapot_fault_sites;
        /* Keep the stub/text extent relationship valid. This isolates the
         * new page-end rule, rather than failing the older bounds rule. */
        damaged->text_end--;
        damaged->stub_end--;
        assert(!mprotect((void *)page,4096,PROT_READ));
    }
    const struct libcheckpoint_contract_record r = {
        .magic = LIBCHECKPOINT_CONTRACT_MAGIC, .version = LIBCHECKPOINT_CONTRACT_VERSION,
        .kind = LIBCHECKPOINT_CONTRACT_KIND_MODULE, .header_size = sizeof(r),
        .capabilities = LIBCHECKPOINT_CAPABILITY_FAULT_TRAINING|LIBCHECKPOINT_CAPABILITY_FAULT_PUBLISHING,
        .fault_sites = &__start_teapot_fault_sites };
    teapot_fault_registry_initialize(&r,(const char *)&r + sizeof(r));
    const struct teapot_fault_window_entry *w = (const void *)__start_teapot_fault_sites.entries;
    uintptr_t pc, copy;
    assert(teapot_fault_resolve_relative((uintptr_t)&w->site.fault_pc,w->site.fault_pc,&pc));
    assert(teapot_fault_resolve_relative((uintptr_t)&w->site.copy_pc,w->site.copy_pc,&copy));
    if (__start_teapot_fault_sites.count==1) {
        uintptr_t end;
        assert(teapot_fault_resolve_relative((uintptr_t)&__start_teapot_fault_sites.text_end,
                                            __start_teapot_fault_sites.text_end,&end));
        assert((pc & ~(uintptr_t)4095)==((end-1) & ~(uintptr_t)4095));
    }
    uint64_t value = 1234567;
    assert(window_test(&value) == value);
    unsigned char original[24]; memcpy(original,(void *)pc,w->site.length);
    teapot_fault_publish_pending(); /* empty fast path must not change bytes */
    assert(!memcmp(original,(void *)pc,w->site.length));
    siginfo_t info = {.si_code = !strcmp(argv[1],"kernel") ? SI_KERNEL : SEGV_MAPERR};
    assert(!teapot_fault_train(SIGSEGV,&info,pc,false,false));
    assert(!teapot_fault_train(SIGSEGV,&info,pc,true,true));
    if (!strcmp(argv[1],"off") || masked_addresses) {
        assert(!teapot_fault_train(SIGSEGV,&info,pc,true,false));
        teapot_fault_publish_pending(); assert(!memcmp(original,(void *)pc,w->site.length)); return 0;
    }
    assert(teapot_fault_train(SIGSEGV,&info,pc,true,false));
    assert(teapot_fault_counter(0,0) == 1);
    teapot_fault_publish_pending(); assert(!memcmp(original,(void *)pc,w->site.length));
    assert(teapot_fault_train(SIGSEGV,&info,copy,true,false)); /* shared count/event */
    assert(teapot_fault_counter(0,0) == 2);
    if (!strcmp(argv[1],"overflow")) {
        for (size_t i = 1; i < __start_teapot_fault_sites.count; ++i) {
            const struct teapot_fault_window_entry *next = w + i;
            uintptr_t fault;
            assert(teapot_fault_resolve_relative((uintptr_t)&next->site.fault_pc,next->site.fault_pc,&fault));
            assert(teapot_fault_train(SIGSEGV,&info,fault,true,false));
            assert(teapot_fault_train(SIGSEGV,&info,fault,true,false));
        }
    }
    if (!strcmp(argv[1],"rw-failure")) failure = 1;
    if (!strcmp(argv[1],"rx-failure")) failure = 2;
    if (!strcmp(argv[1],"fatal-rx")) failure = 3;
    active = 1;
    teapot_fault_publish_pending();
    assert(window_test(&value) == value);
    if (failure) { assert(!memcmp(original,(void *)pc,w->site.length)); return 0; }
    assert(*(const unsigned char *)pc == 0xe9);
    if (!strcmp(argv[1],"overflow")) {
        for (size_t i = 0; i < __start_teapot_fault_sites.count; ++i) {
            const struct teapot_fault_window_entry *next = w + i;
            uintptr_t fault;
            assert(teapot_fault_resolve_relative((uintptr_t)&next->site.fault_pc,next->site.fault_pc,&fault));
            assert(*(const unsigned char *)fault == 0xe9);
        }
    }
    assert(!memcmp(original+5,(const unsigned char *)pc+5,w->site.length-5));
    assert(window_test((void *)(1ULL<<56)) == UINTPTR_MAX);
    assert(window_test((void *)UINTPTR_MAX) == UINTPTR_MAX);
    if (teapot_fault_low_bound) assert(window_test(NULL) == UINTPTR_MAX);
    assert(teapot_fault_train(SIGSEGV,&info,copy,true,false));
    teapot_fault_publish_pending(); /* no second write; already claimed */
    assert(window_test(&value) == value);
    return 0;
}
''')
            command = ["gcc","-O2","-UNDEBUG","-no-pie","-DENABLE_FAULT_TRAINING","-DENABLE_FAULT_PUBLISHING",
                       "-I"+str(runtime/"include"),"check.c","fixed.S",str(runtime/"src/fault_sites.c"),
                       str(runtime/"src/fault_x64.c"),"-Wl,--wrap=teapot_fault_x64_mprotect",
                       "-Wl,--wrap=teapot_fault_x64_can_publish_addresses","-Wl,-z,separate-code","-o","check"]
            result = subprocess.run(command,cwd=root,text=True,capture_output=True,timeout=30)
            self.assertEqual(result.returncode,0,result.stderr)
            receipt=[{"argv":command,"exit":result.returncode,"stdout":result.stdout,"stderr":result.stderr}]
            with (root/"check").open("rb") as stream:
                elf = ELFFile(stream); validate_windows(elf,elf.get_section_by_name("teapot_fault_sites")["sh_addr"])
                symbol = next(s for s in elf.get_section_by_name(".symtab").iter_symbols()
                              if s.name == "teapot_fault_x64_mprotect")
                code = elf.get_section(symbol["st_shndx"])
                instructions = tuple(decoder().disasm(code.data()[symbol["st_value"]-code["sh_addr"]:
                                                                  symbol["st_value"]-code["sh_addr"]+symbol["st_size"]],
                                                     symbol["st_value"]))
                self.assertTrue(any(i.mnemonic=="syscall" for i in instructions))
                self.assertFalse(any(i.mnemonic=="call" for i in instructions))
            for mode in ("on","off","masked","kernel","overflow","rw-failure","rx-failure","fatal-rx","bad-end"):
                result = subprocess.run([str(root/"check"),mode],cwd=root,text=True,capture_output=True,timeout=10)
                receipt.append({"mode":mode,"exit":result.returncode,"stdout":result.stdout,"stderr":result.stderr})
                with self.subTest(mode=mode):
                    self.assertEqual(result.returncode,-6 if mode in ("fatal-rx","bad-end") else 0,result.stdout+result.stderr)
                    if mode == "fatal-rx": self.assertIn("cannot restore executable protections",result.stderr)
                    if mode == "bad-end": self.assertIn("malformed table",result.stderr)
            if os.environ.get("TEAPOT_FAULT_EVIDENCE"):
                import json
                (root/"receipt.json").write_text(json.dumps(receipt,indent=2)+"\n")
                name="native-publisher-last-page" if leading else "native-publisher-ring"
                preserve_evidence(root,Path(os.environ["TEAPOT_FAULT_EVIDENCE"])/name)

    def test_publication_after_real_nested_rollback_and_memlog_restart(self):
        """The real assembly checkpoint/signal/replay path, not a fake restore.

        Eight executions cover adaptation on/off, one/two checkpoint depths,
        and a replay write fault. A real report call precedes the covered
        access. Repeated faults publish only after the rollback safe point.
        """
        from elftools.elf.elffile import ELFFile
        runtime=Path(os.environ.get("TEAPOT_RUNTIME_SOURCE",str(Path(__file__).resolve().parents[1]/"libcheckpoint")))
        self.assertTrue((runtime/"src/fault_sites.c").is_file(),"matching runtime sources required")
        self.assertTrue(shutil.which("cmake"),"matching runtime build required")
        module,section,bounds=self.make_module(bytes.fromhex("488b074889c1c3"))
        add_fault_windows(module,section,bounds)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); module.ir.save_protobuf(root/"in.gtirb")
            commands=(["gtirb-pprinter","--ir","in.gtirb","--asm","fixed.S","--shared","no"],
                ["cmake","-S",str(runtime),"-B","build","-DBUILD_TESTING=OFF",
                 "-DCMAKE_BUILD_TYPE=Release","-DCMAKE_C_FLAGS=-fno-pie",
                 "-DTEAPOT_ENABLE_COVERAGE=OFF","-DTEAPOT_ENABLE_DIFT_RUNTIME=OFF",
                 "-DTEAPOT_BUILD_NESTED_RUNTIME=ON","-DTEAPOT_ENABLE_FAULT_TRAINING=ON",
                 "-DTEAPOT_ENABLE_FAULT_PUBLISHING=ON"],
                ["cmake","--build","build","--target","checkpoint_nested","-j","2"])
            log=[]
            for command in commands:
                result=subprocess.run(command,cwd=root,text=True,capture_output=True,timeout=120)
                log.append({"argv":command,"exit":result.returncode,"stdout":result.stdout,"stderr":result.stderr})
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            (root/"probe.S").write_text(r'''
#include "checkpoint.h"
.text
.global checkpoint_rollback_probe
checkpoint_rollback_probe:
    lea checkpoint_test_transient_body(%rip),%rax
    mov %rax,checkpoint_target_metadata+CHECKPOINT_TARGET_TRAMPOLINE_ADDR(%rip)
    lea .Lrestored(%rip),%rax
    mov %rax,checkpoint_target_metadata+CHECKPOINT_TARGET_RETURN_ADDR(%rip)
    jmp make_checkpoint_integer
.Lrestored:
    mov $1,%eax
    ret
.global report_before_check
report_before_check:
    sub $8,%rsp
    lea test_report_site(%rip),%rdi
    xor %esi,%esi
    mov $TAG_ATTACKER,%edx
.global test_report_site
test_report_site:
    call report_gadget_KASPER_CACHE
    add $8,%rsp
    ret
.section .note.GNU-stack,"",@progbits
''')
            (root/"probe.c").write_text(r'''
#define _GNU_SOURCE
#undef NDEBUG
#include "checkpoint.h"
#include "fault_sites.h"
#include "signal_handler.h"
#include "runtime_contract.h"
#include "runtime_contract_fingerprint.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
extern const struct teapot_fault_site_table __start_teapot_fault_sites;
extern const char LIBCHECKPOINT_CONTRACT_ANCHOR[];
__attribute__((used,section("teapot_contract"),aligned(8)))
static const struct libcheckpoint_contract_record record={
    .magic=LIBCHECKPOINT_CONTRACT_MAGIC,.version=LIBCHECKPOINT_CONTRACT_VERSION,
    .kind=LIBCHECKPOINT_CONTRACT_KIND_MODULE,.header_size=LIBCHECKPOINT_CONTRACT_HEADER_SIZE,
    .fingerprint=LIBCHECKPOINT_CONTRACT_FINGERPRINT,
    .capabilities=LIBCHECKPOINT_CAPABILITY_NESTED|LIBCHECKPOINT_CAPABILITY_FAULT_TRAINING|
                  LIBCHECKPOINT_CAPABILITY_FAULT_PUBLISHING,
    .anchor=LIBCHECKPOINT_CONTRACT_ANCHOR,.fault_sites=&__start_teapot_fault_sites};
extern memory_history_t *memory_history_top;
extern uintptr_t checkpoint_target_metadata[];
extern uint64_t max_checkpoints;
extern void poison_protected_zone(void);
extern int checkpoint_rollback_probe(void);
extern void report_before_check(void);
extern uint64_t window_test(const uint64_t *);
static uint32_t branch_counter;
static uint64_t word=0x5555;
static unsigned nested,restart,step,report_steps;
static void *fault_page;
static void logged_write(uint64_t value) {
    *memory_history_top++=(memory_history_t){.addr=&word,.data=word,.size=8};
    word=value;
}
__attribute__((noreturn)) void checkpoint_test_transient_body(void) {
    if (step++==0) {
        logged_write(0x1111);
        if (nested) {
            assert(checkpoint_cnt==1);
            assert(checkpoint_rollback_probe()==1);
            assert(checkpoint_cnt==1 && word==0x1111);
        }
    } else {
        assert(nested && checkpoint_cnt==2 && word==0x1111);
        logged_write(0x2222);
    }
    if (restart) {
        *memory_history_top++=(memory_history_t){.addr=fault_page,.data=UINT64_MAX,.size=8};
    }
    report_steps++;
    report_before_check();
    window_test((void *)(1ULL<<56));
    abort();
}
int main(int argc,char **argv) {
    assert(argc==3); nested=atoi(argv[1]);restart=atoi(argv[2]);
    fault_page=mmap(NULL,(size_t)sysconf(_SC_PAGESIZE),PROT_READ,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(fault_page!=MAP_FAILED);
    checkpoint_target_metadata[CHECKPOINT_TARGET_BRANCH_COUNTER_ADDR/8]=(uintptr_t)&branch_counter;
    checkpoint_target_metadata[CHECKPOINT_TARGET_FIXED_REG0_SOURCE/8]=UINTPTR_MAX;
    checkpoint_target_metadata[CHECKPOINT_TARGET_FIXED_REG1_SOURCE/8]=UINTPTR_MAX;
    libcheckpoint_enabled=true;setup_signal_handler();poison_protected_zone();
    for (unsigned iteration=0;iteration<4;iteration++) {
        branch_counter=0;max_checkpoints=MAX_CHECKPOINTS;step=0;
        assert(checkpoint_cnt==0 && word==0x5555);
        assert(checkpoint_rollback_probe()==1);
        assert(checkpoint_cnt==0 && word==0x5555 && !in_restore_memlog);
        assert(memory_history_top==memory_history);
    }
    unsigned windows=4*(1+nested);
    assert(report_steps==windows && simulation_statistics.total_ckpt==windows);
    assert(simulation_statistics.rollback_reason[ROLLBACK_SIGSEGV]==windows);
    assert(simulation_statistics.ckpt_depth[0]==4 && simulation_statistics.ckpt_depth[1]==4*nested);
    assert(simulation_statistics.total_bug==1 && simulation_statistics.bug_type[GADGET_KASPER_CACHE]==1);
    const struct teapot_fault_window_entry *entry=(const void *)__start_teapot_fault_sites.entries;
    uintptr_t pc;assert(teapot_fault_resolve_relative((uintptr_t)&entry->site.fault_pc,entry->site.fault_pc,&pc));
    bool enabled=getenv("TEAPOT_FAULT_ADAPTATION")[0]!='0';
    if (*(const unsigned char *)pc!=(enabled?0xe9:0x48)) {
        fprintf(stderr,"unexpected publication: mode=%u byte=%02x count=%u low=%lx\n",
                enabled,*(const unsigned char *)pc,teapot_fault_counter(0,0),teapot_fault_low_bound);
        return 99;
    }
    assert(teapot_fault_counter(0,0)==(enabled?2:0));
    uint64_t value=1234567;assert(window_test(&value)==value);
    printf("windows=%u reports=%lu steps=%u restored=%lx\n",windows,simulation_statistics.total_bug,report_steps,word);
    return 0;
}
''')
            command=["gcc","-O2","-UNDEBUG","-fno-pie","-no-pie","-DDIFT_XOR_MASK=0x300000000000ULL",
                "-DENABLE_NESTED_SPECULATION","-DENABLE_FAULT_TRAINING","-DENABLE_FAULT_PUBLISHING",
                "-I"+str(runtime/"include"),"-Ibuild/include","probe.c","probe.S","fixed.S",
                "build/libcheckpoint_nested.a","-Wl,-z,separate-code","-Wl,--no-as-needed",
                "-lasan","-lm","-ldl","-o","probe"]
            result=subprocess.run(command,cwd=root,text=True,capture_output=True,timeout=60)
            log.append({"argv":command,"exit":result.returncode,"stdout":result.stdout,"stderr":result.stderr})
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            with (root/"probe").open("rb") as stream:
                elf=ELFFile(stream);validate_windows(elf,elf.get_section_by_name("teapot_fault_sites")["sh_addr"])
            for nested in (0,1):
                for restart in (0,1):
                    results=[]
                    for enabled in (0,1):
                        env=dict(os.environ,TEAPOT_FAULT_ADAPTATION=str(enabled),
                                 ASAN_OPTIONS="detect_leaks=0:abort_on_error=1")
                        result=subprocess.run([str(root/"probe"),str(nested),str(restart)],cwd=root,env=env,
                                              text=True,capture_output=True,timeout=20)
                        log.append({"mode":[nested,restart,enabled],"exit":result.returncode,
                                    "stdout":result.stdout,"stderr":result.stderr})
                        results.append(result)
                    for result in results:
                        if result.returncode and os.environ.get("TEAPOT_FAULT_EVIDENCE"):
                            import json
                            (root/"receipt.json").write_text(json.dumps(log,indent=2)+"\n")
                            preserve_evidence(root,Path(os.environ["TEAPOT_FAULT_EVIDENCE"])/"real-rollback-failed")
                        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                    self.assertEqual(results[0].stdout,results[1].stdout)
                    self.assertEqual(results[0].stderr,results[1].stderr)
                    self.assertEqual(results[0].stderr.count("[teapot], 42 KASPER_CACHE,"),1)
            evidence=os.environ.get("TEAPOT_FAULT_EVIDENCE")
            if evidence:
                import json
                (root/"receipt.json").write_text(json.dumps(log,indent=2)+"\n")
                preserve_evidence(root,Path(evidence)/"real-rollback")


if __name__ == "__main__": unittest.main()
