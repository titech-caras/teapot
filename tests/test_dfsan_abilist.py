"""DFSan ABI lists decide what an unwrapped library call does to tags."""
from pathlib import Path
import re
from types import SimpleNamespace
import unittest

import gtirb
from gtirb_rewriting.decoder import GtirbInstructionDecoder

from teapot.arch import X64Architecture
from teapot.configs.blacklist import DIFT_WRAPPER_FUNCTIONS
from teapot.dfsan_abilist import AbiList, call_effect, category
from teapot.passes.preprocessing.dift_ext_call_pass import ExternalCallTags
from teapot.passes.text.dift.x64 import X64TextDiftPropagationLLVMPass

ROOT = Path(__file__).resolve().parents[1]
WRAPPER_SOURCES = ROOT / "libcheckpoint" / "src" / "dift_wrappers"


class AbiListTests(unittest.TestCase):
    def test_categories_follow_dfsan_precedence_and_globs(self):
        abi_list = AbiList("""
fun:both=custom
fun:both=functional
fun:prefix_*=discard
fun:skipped=uninstrumented
fun:typo=disacrd  # not a category
""")
        self.assertEqual(abi_list.categories("both"), {"custom", "functional"})
        self.assertEqual(abi_list.categories("prefix_x"), {"discard"})
        self.assertEqual(abi_list.categories("skipped"), set())
        self.assertEqual(abi_list.categories("typo"), set())

    def test_teapot_list_overrides_llvm_list(self):
        self.assertEqual(category("malloc"), "custom")      # LLVM: discard
        self.assertEqual(category("read"), "custom")        # a Teapot taint source
        self.assertEqual(category("pthread_attr_getstackaddr"), "discard")  # LLVM: "disacrd"
        self.assertEqual(category("isdigit"), "functional")
        self.assertEqual(category("fprintf"), "discard")
        self.assertEqual(category("__dfsw_anything"), "discard")  # LLVM glob
        self.assertIsNone(category("strtok"))

    @unittest.skipUnless(WRAPPER_SOURCES.is_dir(), "requires the libcheckpoint submodule")
    def test_runtime_wrappers_are_exactly_the_libcheckpoint_definitions(self):
        defined = set()
        for path in WRAPPER_SOURCES.glob("*.c*"):
            text = path.read_text()
            defined.update(re.findall(r"^DIFT_WRAPPER\((\w+),", text, re.M))
            defined.update(re.findall(r"^DFSW_BRIDGE\d\([^,]+, (\w+),", text, re.M))
            defined.update("__isoc23_" + name for name in re.findall(r"^DFSW_ISOC23_STRTO\([^,]+, (\w+)\)", text, re.M))
            defined.update(re.findall(r'^extern "C" [^(]*?\b(\w+)__dift_wrapper__\(', text, re.M))
        self.assertEqual(DIFT_WRAPPER_FUNCTIONS, defined)
        self.assertEqual({name for name in defined if category(name) != "custom"}, set())


class CallEffectTests(unittest.TestCase):
    def test_discard_and_unlisted_results_are_untagged(self):
        for name in ("fprintf", "strtok", "malloc"):
            self.assertEqual(call_effect("x64", name), ((), ("rax",)))
            self.assertEqual(call_effect("aarch64", name), ((), ("x0",)))
            self.assertEqual(call_effect("riscv64", name), ((), ("a0",)))

    def test_functional_results_join_integer_arguments(self):
        self.assertEqual(call_effect("x64", "isdigit"), (("rdi",), ("rax",)))
        self.assertEqual(call_effect("riscv64", "isdigit"), (("a0",), ("a0",)))
        # Hard-float values are untracked; an integer predicate of one is untagged.
        self.assertEqual(call_effect("x64", "isnan"), ((), ("rax",)))
        self.assertEqual(call_effect("aarch64", "pow"), ((), ()))
        self.assertEqual(call_effect("riscv64", "pow"), ((), ()))
        # lp64 passes doubles in integer registers; RV long doubles use a pair.
        self.assertEqual(call_effect("riscv64", "pow", soft_float=True), (("a0", "a1"), ("a0",)))
        self.assertEqual(call_effect("riscv64", "expl"), (("a0", "a1"), ("a0", "a1")))
        self.assertEqual(call_effect("riscv64", "nexttoward", soft_float=True), (("a0", "a1", "a2"), ("a0",)))


class ExternalCallTagsTests(unittest.TestCase):
    def call(self, name, *, conditional=False, linked=(), defined=False):
        ir = gtirb.IR()
        module = gtirb.Module(
            name="a.out", isa=gtirb.Module.ISA.ValidButUnsupported,
            byte_order=gtirb.Module.ByteOrder.Little,
            file_format=gtirb.Module.FileFormat.ELF, ir=ir)
        module.aux_data["archInfo"] = gtirb.AuxData({"ISA": "RISCV64"}, "mapping<string,string>")
        text = gtirb.Section(name=".text", module=module)
        plt = gtirb.Section(name=".plt", module=module)
        caller = gtirb.CodeBlock(size=4)
        interval = gtirb.ByteInterval(address=0x1000, contents=bytes.fromhex("ef000000"),
                                      blocks=[caller], section=text)
        stub = gtirb.CodeBlock(size=4)
        gtirb.ByteInterval(address=0x2000, contents=bytes.fromhex("67800000"), blocks=[stub], section=plt)
        if defined:
            callee = gtirb.CodeBlock(size=4)
            gtirb.ByteInterval(address=0x3000, contents=bytes.fromhex("67800000"), blocks=[callee], section=plt)
        else:
            callee = gtirb.ProxyBlock(module=module)
        imported = gtirb.Symbol(name=name, payload=callee, module=module)
        alias = gtirb.Symbol(name=name + "@plt", payload=stub, module=module)
        interval.symbolic_expressions[0] = gtirb.SymAddrConst(0, alias)
        module.aux_data["symbolForwarding"] = gtirb.AuxData({alias: imported}, "mapping<UUID,UUID>")
        ir.cfg.add(gtirb.Edge(caller, stub, gtirb.Edge.Label(
            type=gtirb.EdgeType.Call if not conditional else gtirb.EdgeType.Branch, conditional=conditional)))
        tags = ExternalCallTags("riscv64", linked_function_symbols=linked)
        return tags.effect(caller, text, GtirbInstructionDecoder(module.isa)), tags

    def test_unwrapped_import_gets_its_dfsan_effect(self):
        self.assertEqual(self.call("getenv")[0], ((), ("a0",)))
        effect, tags = self.call("htonl")
        self.assertEqual(effect, ((), ("a0",)))
        self.assertEqual(tags.unlisted, {"htonl"})

    def test_identity_wrapped_linked_defined_and_conditional_calls_are_left_alone(self):
        self.assertIsNone(self.call("isdigit")[0])                    # a0 -> a0
        self.assertIsNone(self.call("memcpy__dift_wrapper__")[0])
        self.assertIsNone(self.call("signal__teapot_wrapper__")[0])
        self.assertIsNone(self.call("getenv", linked={"getenv"})[0])
        self.assertIsNone(self.call("getenv", defined=True)[0])
        self.assertIsNone(self.call("getenv", conditional=True)[0])


class TextDiftCallTests(unittest.TestCase):
    def ir(self, effect):
        arch = X64Architecture()
        dift = X64TextDiftPropagationLLVMPass(SimpleNamespace(abi=arch.abi), None, None, arch,
                                              dift_layout=SimpleNamespace(xor_mask=0))
        dift.external_calls = SimpleNamespace(effect=lambda *_: effect)
        dift._reset()
        dift._external_call_tags(None, [SimpleNamespace(size=5, mnemonic="call", operands=[])])
        return "\n".join(dift.llvm_ir)

    def test_functional_call_joins_argument_tags_into_the_result(self):
        ir = self.ir((("rdi", "rsi"), ("rax",)))
        self.assertIn("or i8", ir)
        self.assertRegex(ir, r"@dift_reg_tags, i64 0, i64 5\b")   # rdi
        self.assertRegex(ir, r"@dift_reg_tags, i64 0, i64 4\b")   # rsi
        self.assertRegex(ir, r"@dift_reg_tags, i64 0, i64 0\b")   # rax

    def test_discard_call_clears_the_result_tag(self):
        ir = self.ir(((), ("rax",)))
        self.assertNotIn("or i8", ir)
        self.assertEqual(re.findall(r"@dift_reg_tags, i64 0, i64 (\d+)", ir), ["0"])

    def test_no_effect_emits_nothing(self):
        self.assertEqual(self.ir(None), "")


if __name__ == "__main__":
    unittest.main()
