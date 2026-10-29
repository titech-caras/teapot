"""Execute production CZERO tag replay for each profile and operand alias."""
import ctypes
import unittest

import llvmlite.binding as llvm

from test_riscv_pure_codegen import architecture, build_effect, conditional_zero, replay


class RiscvConditionalZeroTagTests(unittest.TestCase):
    def test_selected_source_tag_and_zero_arm_in_both_profiles(self):
        llvm.initialize_native_target()
        llvm.initialize_native_asmprinter()
        for profile in (None, "lp64-pure"):
            for mnemonic in ("czero.eqz", "czero.nez"):
                for rd, source, condition in ((10, 11, 12), (12, 11, 12),
                        (11, 11, 12), (11, 11, 11), (10, 11, 11),
                        (10, 0, 12), (10, 11, 0)):
                    dift = replay(architecture(profile))
                    inst = conditional_zero(mnemonic, rd, source, condition)
                    _, _, effects = build_effect(dift, inst)
                    body = "\n".join(dift.llvm_ir)
                    module = llvm.parse_assembly(dift._format_llvm_ir(
                        body, target_triple=llvm.get_default_triple()))
                    target = llvm.Target.from_default_triple().create_target_machine()
                    module.data_layout = str(target.target_data)
                    module.verify()
                    with llvm.create_mcjit_compiler(module, target) as engine:
                        engine.finalize_object()
                        run = ctypes.CFUNCTYPE(None)(engine.get_function_address("func"))
                        tags = (ctypes.c_uint8 * 48).from_address(
                            engine.get_global_value_address("dift_reg_tags"))
                        scratch = (ctypes.c_uint64 * 1).from_address(
                            engine.get_global_value_address("scratchpad"))
                        for value in (0, 7):
                            for source_tag in (0, 0x35):
                                with self.subTest(profile=profile, mnemonic=mnemonic,
                                        shape=(rd, source, condition), value=value,
                                        source_tag=source_tag):
                                    tags[:] = [0x5a] * 48
                                    tags[condition] = 0x80
                                    tags[source] = source_tag
                                    tags[0] = 0
                                    original = list(tags)
                                    scratch[0] = value if condition else 0
                                    zeroes = (scratch[0] == 0) == (mnemonic == "czero.eqz")
                                    expected = 0 if zeroes else tags[source]
                                    run()
                                    original[rd] = expected
                                    self.assertEqual(list(tags), original)
