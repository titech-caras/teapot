"""Profile/contract/cache predicates, using independently encoded ELF bytes."""
from dataclasses import replace
import struct
import gtirb
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from elftools.elf.elffile import ELFFile

from teapot.arch import get_arch
from gtirb_rewriting.abi import _ABIS
from teapot.pipeline import InstrumentationOptions, TeapotPipeline
from teapot.riscv_profile import (DEFAULT, PURE, PURE_ABI, INTERPRETERS,
                                 RiscvProfileError, validate_arch_attribute_record, validate_arch_attributes,
                                 validate_arch_string, validate_compiler, validate_elf_header, validate_flags)
from teapot.runtime_contract import RuntimeContractError, capability_bits, load_runtime_contract
from experiments.reusable_libraries.targets import mode_metadata
from experiments.reusable_libraries.validate_link import validate_mode_contract
from runtime_contract_support import runtime_contract
from test_runtime_contract import edited_contract
ARCH = "rv64i2p1_m2p0_a2p1_c2p0_zicond1p0_zicsr2p0_zifencei2p0_zmmul1p0_zaamo1p0_zalrsc1p0_zca1p0"
NOP = b"\x13\0\0\0"
RET = b"\x67\x80\0\0"


def module_fixture(code=NOP + RET):
    module = gtirb.Module(name="pure", isa=gtirb.Module.ISA.ValidButUnsupported,
                          file_format=gtirb.Module.FileFormat.ELF,
                          byte_order=gtirb.Module.ByteOrder.Little)
    gtirb.IR(modules=[module])
    module.aux_data["archInfo"] = gtirb.AuxData({"ISA": "RISCV64"}, "mapping<string,string>")
    section = gtirb.Section(name=".text", module=module,
                           flags={gtirb.Section.Flag.Readable, gtirb.Section.Flag.Executable,
                                  gtirb.Section.Flag.Loaded})
    interval = gtirb.ByteInterval(address=0x1000, contents=code, section=section)
    block = gtirb.CodeBlock(size=len(code), byte_interval=interval)
    return module, interval, block


def elf_fixture(code=NOP + RET, mappings=(("$x", 0),), *, flags=1, arch=ARCH,
                elf_type=1, executable=True, attrs=True, integer_attrs=(), text_name=".text", pf_x_data=None):
    """ELF64 bytes built directly, independently of any target compiler."""
    def uleb(value):
        result = bytearray()
        while value >= 128:
            result.append((value & 127) | 128); value >>= 7
        result.append(value)
        return bytes(result)
    payload = b"\x04\x10\x05" + arch.encode() + b"\0" + b"".join(
        uleb(tag) + uleb(value) for tag, value in integer_attrs)
    subsection = b"\x01" + struct.pack("<I", 5 + len(payload)) + payload
    attribute = b"A" + struct.pack("<I", 10 + len(subsection)) + b"riscv\0" + subsection
    names = b"\0"
    symbols = bytes(24)
    for item in mappings:
        name, offset = item[:2]
        info = item[2] if len(item) == 3 else 0  # LOCAL/NOTYPE only.
        name_at = len(names); names += name.encode() + b"\0"
        symbols += struct.pack("<IBBHQQ", name_at, info, 0, 1, offset, 0)
    sections = [
        (text_name, 1, 6 if executable else 2, code, 0, 0, 2, 0),
        (".riscv.attributes" if attrs else ".not-attributes", 0x70000003, 0,
         attribute, 0, 0, 1, 0),
        (".strtab", 3, 0, names, 0, 0, 1, 0),
        (".symtab", 2, 0, symbols, 3, len(mappings) + 1, 8, 24),
    ]
    if pf_x_data is not None:
        sections.extend((name, 1, 2, data, 0, 0, 2, 0) for name, data in pf_x_data)
    shnames, offsets = b"\0", []
    for name, *_ in sections:
        offsets.append(len(shnames)); shnames += name.encode() + b"\0"
    offsets.append(len(shnames)); shnames += b".shstrtab\0"
    sections.append((".shstrtab", 3, 0, shnames, 0, 0, 1, 0))
    body, headers = bytes(120 if pf_x_data is not None else 64), [bytes(64)]
    alloc_last = 0
    for name_at, (_, kind, section_flags, data, link, info, align, entsize) in zip(offsets, sections):
        body += bytes((-len(body)) % align)
        offset = len(body); body += data
        address = offset - 120 if pf_x_data is not None and section_flags & 2 else 0
        if section_flags & 2:
            alloc_last = len(body)
        headers.append(struct.pack("<IIQQQQIIQQ", name_at, kind, section_flags, address,
                                   offset, len(data), link, info, align, entsize))
    body += bytes((-len(body)) % 8)
    shoff = len(body)
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    ehdr = struct.pack("<16sHHIQQQIHHHHHH", ident, elf_type, 243, 1, 0,
                       64 if pf_x_data is not None else 0, shoff, flags,
                       64, 56, int(pf_x_data is not None), 64, len(headers), len(headers) - 1)
    phdr = (struct.pack("<IIQQQQQQ", 1, 5, 120, 0, 0, alloc_last - 120, alloc_last - 120, 2)
            if pf_x_data is not None else b"")
    return ehdr + phdr + body[64 + len(phdr):] + b"".join(headers)


class RiscvPureProfileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def contract(self, edit=None):
        def change(data):
            data['abi'].update(PURE_ABI)
            if edit:
                edit(data)
        return load_runtime_contract(edited_contract(self.root, 'riscv64-nofp', change))

    def input(self):
        module, interval, _ = module_fixture()
        interval.address = 0
        original = self.root / 'input.so'
        original.write_bytes(elf_fixture(elf_type=3))
        return module, original

    def test_abi_bits_separate_lp64_and_lp64d(self):
        for profile, allowed in ((DEFAULT, (4, 5)), (PURE, (0, 1))):
            for flags in range(32):
                if flags in allowed:
                    self.assertEqual(validate_flags(flags, profile), flags)
                else:
                    with self.assertRaises(RiscvProfileError):
                        validate_flags(flags, profile)
        for value in (True, None, -1, '1'):
            with self.assertRaises(RiscvProfileError):
                validate_flags(value, PURE)
        for profile in (DEFAULT, PURE):
            with self.subTest(profile=profile), self.assertRaises(RiscvProfileError):
                validate_flags(0x10, profile)  # EF_RISCV_TSO is not an ABI permission.

    def test_priv_spec_attributes_are_informational_but_validated_and_recorded(self):
        import io
        raw = elf_fixture(integer_attrs=((8, 1), (10, 12), (12, 0)))
        elf = ELFFile(io.BytesIO(raw))
        validate_elf_header(elf)
        record = validate_arch_attribute_record(elf)
        self.assertEqual(record['priv_spec'], {'major': 1, 'minor': 12, 'revision': 0})
        self.assertEqual(record['integer_attributes'], {'4': 16, '8': 1, '10': 12, '12': 0})
        self.assertEqual(validate_arch_attributes(elf), record['architectures'])
        for attrs in (((8, 1), (8, 2)), ((20, 0),)):
            with self.subTest(attrs=attrs), self.assertRaises(RiscvProfileError):
                validate_arch_attributes(ELFFile(io.BytesIO(elf_fixture(integer_attrs=attrs))))

    def test_card_attributes_and_compiler_defaults_are_not_replaced(self):
        self.assertIn('zicond', validate_arch_string('rv64i2p1_m2p0_a2p1_c2p0_zicond1p0_zicsr2p0_zifencei2p0'))
        for text in ('rv64imafd', 'rv64imac_zbb1p0', 'rv64imac_zba', 'rv32imac', 'rv64imac_v1p0'):
            with self.assertRaises(ValueError):
                validate_arch_string(text)
        macros = '#define __riscv_xlen 64\n#define __riscv_float_abi_soft 1\n#define __riscv_zicond 1000000\n'
        with patch('teapot.riscv_profile.subprocess.run', return_value=SimpleNamespace(stdout=macros)) as run:
            self.assertIn('__riscv_zicond', validate_compiler('/bound/gcc'))
            self.assertEqual(run.call_args.args[0], ['/bound/gcc', '-dM', '-E', '-x', 'c', '/dev/null'])
        for wrong in ('#define __riscv_flen 64\n', '#define __riscv_zbb 1\n'):
            with patch('teapot.riscv_profile.subprocess.run', return_value=SimpleNamespace(stdout=macros + wrong)):
                with self.assertRaises(ValueError):
                    validate_compiler('/bound/gcc')

    def test_interpreter_uses_the_first_c_string_as_the_loader_does(self):
        import io
        class Interp(dict):
            def data(self):
                return self['bytes']
        elf = ELFFile(io.BytesIO(elf_fixture(elf_type=2)))
        lp64 = INTERPRETERS[PURE].encode()
        for raw in (lp64 + b'\0', lp64 + b'\0' + lp64 + b'\0'):
            with patch.object(elf, 'iter_segments', return_value=iter([Interp(p_type='PT_INTERP', bytes=raw)])):
                validate_elf_header(elf, role='executable')
        wrong = INTERPRETERS[DEFAULT].encode() + b'\0' + lp64 + b'\0'
        with patch.object(elf, 'iter_segments', return_value=iter([Interp(p_type='PT_INTERP', bytes=wrong)])):
            with self.assertRaisesRegex(RiscvProfileError, 'another interpreter'):
                validate_elf_header(elf, role='executable')

    def test_default_float_requirement_stays_and_pure_is_explicit(self):
        module, _ = self.input(); arch = get_arch(module); abi = arch.register_abi(_ABIS)
        options = InstrumentationOptions()
        with self.assertRaisesRegex(RuntimeContractError, 'floating-point'):
            runtime_contract('riscv64-nofp').check(arch, abi, options)
        contract = self.contract()
        bits, _ = contract.check(arch, abi, options, riscv_profile=PURE)
        self.assertFalse(bits & capability_bits({'riscv64_float_state'}))
        with self.assertRaisesRegex(RuntimeContractError, 'does not know'):
            contract.check(arch, abi, options)
        capable = replace(contract, capabilities=contract.capabilities | {'riscv64_float_state'})
        with self.assertRaisesRegex(RuntimeContractError, 'integer-only'):
            capable.check(arch, abi, options, riscv_profile=PURE)

    def test_partial_or_false_pure_abi_is_not_accepted_on_load(self):
        for key in PURE_ABI:
            def missing(data):
                del data['abi'][key]
            with self.assertRaisesRegex(RuntimeContractError, 'partial'):
                self.contract(missing)
        with self.assertRaisesRegex(RuntimeContractError, 'partial'):
            self.contract(lambda data: data['abi'].__setitem__('riscv.fp_policy', 'unknown'))


    def test_pure_adaptive_combination_refuses_before_input_or_emission(self):
        import gtirb
        for options in (InstrumentationOptions(enable_fault_training=True),
                        InstrumentationOptions(enable_fault_training=True, enable_fault_publishing=True)):
            pipeline = TeapotPipeline(gtirb.IR(), options=options, riscv_profile=PURE)
            with self.subTest(options=options), self.assertRaisesRegex(ValueError, 'no adaptive backend'):
                pipeline.run()


    def test_mode_manifest_refuses_mixed_profiles_and_abi(self):
        pure = mode_metadata('RISCV64', 'riscv64-lp64-pure')
        manifest = dict(pure, components=[dict(pure, component_id='one')])
        self.assertEqual(validate_mode_contract(manifest), ('RISCV64', 'riscv64-lp64-pure'))
        for field, value in (('riscv_profile', DEFAULT), ('riscv_abi', {})):
            mixed = dict(manifest, components=[dict(manifest['components'][0], **{field: value})])
            with self.assertRaises(ValueError):
                validate_mode_contract(mixed)
        self.assertNotIn('riscv_profile', mode_metadata('RISCV64', 'riscv64'))


if __name__ == '__main__':
    unittest.main()
