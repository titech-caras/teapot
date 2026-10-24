"""A jump's return address is untainted, independently of its target's tag."""
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

import gtirb

from teapot.arch import RISCV64Architecture
from teapot.arch.decoders import riscv64_decoder
from teapot.passes.text.dift.riscv64 import RISCV64TextDiftPropagationLLVMPass
from teapot.passes.transient.lazy_dift import transient_replay_pass


class RISCVLinkDiftTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("riscv64-linux-gnu-gcc") and shutil.which("qemu-riscv64"),
                         "requires RV64 compiler and QEMU")
    def test_link_writes_clear_only_the_destination_in_both_paths(self):
        # Include rd == rs1: its old tag must not survive the unchanged-tag
        # optimization. The production decoder expands compressed aliases.
        cases = (
            ("jal ra", "ef000000", 1), ("jal t0", "ef020000", 5),
            ("jalr ra,a1", "e7800500", 1), ("jalr ra,ra", "e7800000", 1),
            ("c.jalr a0", "0295", 1), ("c.jalr ra", "8290", 1),
            ("j", "6f000000", -1), ("jr a1", "67800500", -1),
            ("ret", "67800000", -1), ("c.j", "01a0", -1),
            ("c.jr a0", "0285", -1), ("c.ret", "8280", -1),
        )
        arch = RISCV64Architecture()
        for transient in (False, True):
            for label, encoding, cleared in cases:
                with self.subTest(transient=transient, instruction=label), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    inst = next(riscv64_decoder().disasm(bytes.fromhex(encoding), 0x1000))
                    block = gtirb.CodeBlock(size=inst.size)
                    gtirb.ByteInterval(address=inst.address, contents=bytes(inst.bytes), blocks=[block])
                    manager = SimpleNamespace(abi=arch.abi, add_live_registers=Mock())
                    args = (manager, None, None)
                    options = {"dift_layout": SimpleNamespace(xor_mask=0)}
                    dift = (transient_replay_pass(arch, *args, **options) if transient else
                            RISCV64TextDiftPropagationLLVMPass(*args, arch, **options))
                    dift._reset()
                    dift.rewriting_ctx = SimpleNamespace(_abi=arch.abi)
                    # Collect the real visitor's replay before its block-end
                    # flush. Only insertion bookkeeping is replaced here.
                    dift._current_instructions = [inst, inst]
                    dift.port_reader = None
                    dift.insert_at = Mock()
                    dift.visit_inst(inst, 0, 0, block)
                    ir = dift._parse_and_optimize_llvm(dift._format_llvm_ir(
                        "\n".join(dift.llvm_ir), target_triple=dift.target_triple))
                    (root / "replay.o").write_bytes(dift.target_machine.emit_object(ir))
                    (root / "check.c").write_text(f"""
extern unsigned char dift_reg_tags[48];
extern void func(void);
int main(void) {{
    for (int i = 0; i < 48; ++i) dift_reg_tags[i] = 0x5a;
    func();
    for (int i = 0; i < 48; ++i)
        if (dift_reg_tags[i] != (i == {cleared} ? 0 : 0x5a)) return 1;
    return 0;
}}
""")
                    built = subprocess.run([
                        "riscv64-linux-gnu-gcc", "-O2", "-no-pie", "-march=rv64gc", "-mabi=lp64d",
                        "-Wl,--no-relax", root / "check.c", root / "replay.o", "-o", root / "check",
                    ], capture_output=True, text=True, timeout=30)
                    self.assertEqual(built.returncode, 0, built.stderr)
                    ran = subprocess.run(["qemu-riscv64", "-L", "/usr/riscv64-linux-gnu", root / "check"],
                                         capture_output=True, text=True, timeout=15)
                    self.assertEqual(ran.returncode, 0, ran.stderr)
