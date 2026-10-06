import struct
import unittest

import gtirb

from teapot.arch import AArch64Architecture, RISCV64Architecture
from teapot.fault_risc import (
    DEAD, DESTINATION, MEMLOG, ORIG, SHADOW, Recipe, BoundaryMasks,
    branch, choose_recipe, decode_load, guard_template, ordinary_registers,
    resolve_template,
)
from teapot.liveness import LiveRegisterManager, LivenessMetadataError
from test_live_register_preservation import make_module


def word(value):
    return struct.pack("<I", value)


class RiscLoadTests(unittest.TestCase):
    def test_a64_vocabulary_and_ea(self):
        cases = (
            (0xf9400441, 8, 2, 1, 8, 255, 0, 0),       # ldr x1,[x2,#8]
            (0xf85ff041, 8, 2, 1, -1, 255, 0, 0),      # ldur x1,[x2,#-1]
            (0x3863d841, 1, 2, 1, 0, 3, 6, 0),         # ldrb w1,[x2,w3,sxtw]
            (0xf863f841, 8, 2, 1, 0, 3, 7, 3),         # ldr x1,[x2,x3,sxtx #3]
            (0xb9800041, 4, 2, 1, 0, 255, 0, 0),       # ldrsw x1,[x2]
        )
        for encoding, width, base, dest, disp, index, ext, shift in cases:
            with self.subTest(encoding=hex(encoding)):
                load = decode_load("aarch64", word(encoding))
                self.assertIsNotNone(load)
                self.assertEqual((load.width, load.base, load.destination, load.displacement,
                                  load.index, load.extension, load.shift),
                                 (width, base, dest, disp, index, ext, shift))
                self.assertEqual(load.code, word(encoding))
        for encoding in (0xf9000441, 0xf8408441, 0xf8408c41, 0xa9400441,
                         0x58000041, 0xc85f7c41, 0xc8dffc41, 0x3dc00041,
                         0xf9800041, 0xf94003e1, 0xf94003a1, 0xf9400241,
                         0xf940005f, 0xf9400052, 0xf940005d):
            with self.subTest(refused=hex(encoding)):
                self.assertIsNone(decode_load("aarch64", word(encoding)))

    def test_rv_vocabulary_and_compressed_widening(self):
        for funct3, width in ((0, 1), (1, 2), (2, 4), (3, 8), (4, 1), (5, 2), (6, 4)):
            load = decode_load("riscv64", word(0xfff00003 | 12 << 15 | funct3 << 12 | 11 << 7))
            self.assertEqual((load.width, load.base, load.destination, load.displacement), (width, 12, 11, -1))
        for width, funct3 in ((4, 2), (8, 3)):
            for bits in range(256):
                # All immediate bit patterns and non-fp compact base/destination.
                compressed = funct3 << 13 | (bits & 7) << 10 | 1 << 7 | ((bits >> 3) & 3) << 5 | 2 << 2
                load = decode_load("riscv64", struct.pack("<H", compressed))
                self.assertIsNotNone(load)
                self.assertEqual((load.width, load.base, load.destination, load.input_size), (width, 9, 10, 2))
                widened = decode_load("riscv64", load.code)
                self.assertEqual((widened.width, widened.base, widened.destination, widened.displacement),
                                 (width, 9, 10, load.displacement))
        for encoding in (0x00b63023, 0x100635af, 0x00063587, 0x00063503 | 7 << 12,
                         0x00013083, 0x0001b083, 0x00023083, 0x00043083, 0x00063003,
                         0x00063103, 0x00063183, 0x00063203, 0x00063403):
            self.assertIsNone(decode_load("riscv64", word(encoding)), hex(encoding))

    def test_destination_and_original_only_dead_recipe(self):
        for isa, ordinary, alias in (("aarch64", 0xf9400441, 0xf9400421),
                                      ("riscv64", 0x00863583, 0x0085b583)):
            load = decode_load(isa, word(ordinary))
            recipe = choose_recipe(load, MEMLOG)
            self.assertEqual(recipe.template, DESTINATION)
            self.assertEqual(recipe.bootstrap, load.destination)
            aliased = decode_load(isa, word(alias))
            self.assertIsNone(choose_recipe(aliased, ORIG))
            recipe = choose_recipe(aliased, ORIG, {0, 2, 3, 4, 8, 18, 29, 31, 17})
            self.assertEqual(recipe.template, DEAD)
            self.assertIn(recipe.bootstrap, ordinary_registers(isa))
            self.assertNotIn(recipe.bootstrap, aliased.address_inputs)
            for origin in (MEMLOG, SHADOW, 0, 4):
                self.assertIsNone(choose_recipe(aliased, origin, {17}))


class RiscBoundaryProofTests(unittest.TestCase):
    def fixtures(self):
        for isa, arch, gtisa, code in (
            ("aarch64", AArch64Architecture(), gtirb.Module.ISA.ARM64, "210440f9c0035fd6"),
            ("riscv64", RISCV64Architecture(), gtirb.Module.ISA.ValidButUnsupported, "83b5850067800000"),
        ):
            _, module, block, abi, registers = make_module(arch, gtisa, bytes.fromhex(code))
            yield isa, module, block, abi, registers

    def test_exact_mask_boundary_missing_and_stale_fail_closed(self):
        for isa, module, block, abi, registers in self.fixtures():
            manager = LiveRegisterManager(module, abi)
            proofs = BoundaryMasks(manager, [block], isa)
            self.assertEqual(proofs.dead_gprs(block, 0), set())
            # Use a mask naming everything live except one explicit register.
            name = "x17" if isa == "aarch64" else "t1"
            number = 17 if isa == "aarch64" else 6
            wanted = abi.get_register(name)
            all_live = (1 << len(registers)) - 1
            manager.masks[gtirb.Offset(block, 0)] = all_live & ~(1 << registers.index(wanted))
            manager.masks[gtirb.Offset(block, 1)] = 0
            proofs = BoundaryMasks(manager, [block], isa)
            self.assertEqual(proofs.dead_gprs(block, 0), {number})
            manager.masks[gtirb.Offset(block, 0)] = all_live
            self.assertEqual(proofs.dead_gprs(block, 0), set())
            manager.masks[gtirb.Offset(block, 0)] = all_live & ~(1 << registers.index(wanted))
            self.assertEqual(proofs.dead_gprs(block, 1), set())
            self.assertEqual(proofs.dead_gprs(block, 4), set())
            module.aux_data["liveRegisterSets"].data = dict(manager.masks)
            self.assertEqual(proofs.dead_gprs(block, 0), set())
            proofs = BoundaryMasks(manager, [block], isa)
            block.byte_interval.contents = bytes(4) + block.byte_interval.contents
            block.size += 4
            self.assertEqual(proofs.dead_gprs(block, 0), set())

    def test_invalid_producer_tables_rejected(self):
        for isa, module, block, abi, registers in self.fixtures():
            module.aux_data["liveRegisterFlagRule"].data = "call-boundary"
            with self.assertRaises(LivenessMetadataError):
                LiveRegisterManager(module, abi)

    def test_snapshot_does_not_survive_a_split(self):
        for isa, module, block, abi, registers in self.fixtures():
            manager = LiveRegisterManager(module, abi)
            manager.masks[gtirb.Offset(block, 0)] = 0
            proofs = BoundaryMasks(manager, [block], isa)
            self.assertTrue(proofs.dead_gprs(block, 0))
            block.size -= 4
            self.assertEqual(proofs.dead_gprs(block, 0), set())


class RiscEncodingTests(unittest.TestCase):
    def test_branch_edges_and_halfword_rv(self):
        for isa, step, reach in (("aarch64", 4, 1 << 27), ("riscv64", 2, 1 << 20)):
            pc = 0x10000000 + (2 if isa == "riscv64" else 0)
            for delta in (-reach, -step, 0, step, reach - step):
                encoded = branch(isa, pc, pc + delta)
                self.assertEqual(encoded & (0xfc000000 if isa == "aarch64" else 0xfff),
                                 0x14000000 if isa == "aarch64" else 0x6f)
            for delta in (-reach - step, reach, 1):
                with self.assertRaises(ValueError):
                    branch(isa, pc, pc + delta)

    def test_templates_copy_word_and_relocation_reconstruction(self):
        for isa, encodings in (("aarch64", (0xf9400441, 0xf9400421, 0xf863f841)),
                               ("riscv64", (0x00863583, 0x0085b583))):
            for encoding in encodings:
                load = decode_load(isa, word(encoding))
                recipe = choose_recipe(load, ORIG, {17})
                template = guard_template(load, recipe)
                if isa == "aarch64":
                    policy = [r for r in template.relocations if r.target == "policy"]
                    self.assertEqual([r.kind for r in policy], ["page", "lo12"])
                    self.assertEqual(policy[1].offset - policy[0].offset, 8)
                    self.assertEqual(struct.unpack_from("<I", template.code, policy[0].offset + 4)[0],
                                     0xd3400000 | 55 << 10 | recipe.temp0 << 5 | recipe.temp0)
                self.assertEqual(template.code[template.copy_offset:template.copy_offset + 4], load.code)
                self.assertEqual(len(template.code) % 4, 0)
                start = 0x100000 + (2 if isa == "riscv64" else 0)
                targets = {"spill": 0x204ff8, "policy": 0x300800,
                           "return": start - 500, "rollback": 0x180000}
                resolved = resolve_template(template, start, targets)
                self.assertEqual(resolved[template.copy_offset:template.copy_offset + 4], load.code)
                self.assertNotEqual(resolved, template.code)
                self.assertEqual(len(resolved), len(template.code))
                with self.assertRaises(ValueError):
                    guard_template(load, Recipe(2, 3, 4, DESTINATION))
                with self.assertRaises(ValueError):
                    resolve_template(template, start, {**targets, "return": 1 << 63})
                with self.assertRaises(ValueError):
                    resolve_template(template, start, {**targets, "policy": 1 << 63})


if __name__ == "__main__":
    unittest.main()
