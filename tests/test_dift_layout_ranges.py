import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from teapot.datacls.dift_layout import DiftLayout, LAYOUTS, DEFAULT_LAYOUTS


class DiftLayoutRangesTest(unittest.TestCase):
    def test_native_secondary_allocations_have_high_mapping_headroom(self):
        # Shared objects, allocator reservations, and large mmap-backed objects
        # need more than the top 256 MiB. Reserve room for these application
        # mappings as well as their disjoint DIFT tags (checked below).
        for name, user_end in (("aarch64-vma39", 1 << 39),
                               ("aarch64-vma48", 1 << 48),
                               ("riscv64-sv39", 1 << 38)):
            layout = LAYOUTS[name]
            for distance in (512 << 20, 2 << 30):
                with self.subTest(layout=name, distance=distance):
                    address = user_end - distance
                    self.assertTrue(any(lo <= address < hi for lo, hi in layout.app_ranges))

    def test_x64_default_covers_modern_asan_heap(self):
        self.assertEqual(DEFAULT_LAYOUTS["x64"], "x64-la48-asan-new")
        layout = LAYOUTS[DEFAULT_LAYOUTS["x64"]]
        heap = 0x503000000010
        self.assertTrue(any(lo <= heap < hi for lo, hi in layout.app_ranges))
        self.assertEqual(heap ^ layout.xor_mask, 0x603000000010)

    def test_profile_shadows_do_not_overlap_addressable_ranges(self):
        for layout in LAYOUTS.values():
            with self.subTest(layout=layout.name):
                granularity = layout.xor_mask & -layout.xor_mask
                for start, end in layout.app_ranges:
                    while start < end:
                        chunk_end = min(end, (start // granularity + 1) * granularity)
                        shadow_start = start ^ layout.xor_mask
                        shadow_end = ((chunk_end - 1) ^ layout.xor_mask) + 1
                        for app_start, app_end in layout.app_ranges:
                            self.assertFalse(
                                shadow_start < app_end and app_start < shadow_end,
                                (layout.name, hex(shadow_start), hex(app_start)))
                        start = chunk_end

    def test_python_rejects_overlapping_layouts(self):
        for name, end in (("aarch64-vma42", 0x20000000000),
                          ("riscv64-sv39", 0x2000000000)):
            layout = LAYOUTS[name]
            ranges = list(layout.app_ranges)
            ranges[-2] = (ranges[-2][0], end)
            with self.subTest(layout=name), self.assertRaisesRegex(ValueError, "overlap"):
                replace(layout, app_ranges=tuple(ranges))

    def test_checks_asan_and_range_boundaries(self):
        for ranges in (((0, 16), (8, 32)), ((32, 32),), ((32, 8),)):
            with self.subTest(ranges=ranges), self.assertRaises(ValueError):
                DiftLayout("invalid", "x64", 0x1000, 0x2000, ranges)
        with self.assertRaisesRegex(ValueError, "ASan"):
            DiftLayout("invalid", "x64", 0x1000, 0x1000, ((0, 16),))

    def test_xor_ranges_split_at_every_changed_bit_boundary(self):
        # A multi-bit XOR reverses chunk order, not bytes within a chunk.
        DiftLayout("valid", "x64", 0x3000, 0x10000, ((0, 0x2000),))
        with self.assertRaisesRegex(ValueError, "overlap"):
            DiftLayout("invalid", "x64", 0x3000, 0x10000,
                       ((0, 0x2000), (0x2800, 0x2900)))

    def test_cmake_validates_profiles_and_rejects_overrides(self):
        source = Path(__file__).resolve().parents[1] / "libcheckpoint/cmake/DiftLayout.cmake"
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "CMakeLists.txt"
            project = ('cmake_minimum_required(VERSION 3.16)\n'
                       'project(LayoutValidation NONE)\n'
                       'set(CMAKE_INSTALL_DATADIR share)\n')
            command = ["cmake", "-S", directory, "-B", str(Path(directory) / "build")]
            script.write_text(project + 'set(CHECKPOINT_ARCH_NAME "x64")\n' +
                              f'include("{source}")\n' +
                              'if(NOT TEAPOT_DIFT_LAYOUT STREQUAL "x64-la48-asan-new")\n'
                              'message(FATAL_ERROR "wrong x64 default")\nendif()\n')
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            for layout in LAYOUTS.values():
                script.write_text(
                    project +
                    f'set(TEAPOT_DIFT_LAYOUT "{layout.name}")\n'
                    f'set(CHECKPOINT_ARCH_NAME "{layout.arch}")\n'
                    f'include("{source}")\n')
                result = subprocess.run(command, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
            for mask, offset, ranges in (
                    ("0x20000000000", "0x1000000000",
                     "0x5000000000:0x20000000000 0x3fff0000000:0x40000000000"),
                    ("0x2000000000", "0xd55550000",
                     "0x1555550000:0x2000000000 0x3ff0000000:0x4000000000"),
                    ("0x1000", "0x1000", "0x0:0x10"),
                    ("0x1000", "0x2000", "0x0:0x10 0x8:0x20"),
                    ("0x1000", "0x2000", "0x20:0x10")):
                script.write_text(
                    project +
                    'set(TEAPOT_DIFT_LAYOUT "x64-la48")\n'
                    'set(CHECKPOINT_ARCH_NAME "x64")\n'
                    f'include("{source}")\n'
                    'set(TEAPOT_DIFT_LAYOUT "invalid")\n'
                    f'teapot_dift_layout(invalid ARCH x64 XOR_MASK {mask} '
                    f'ASAN_SHADOW_OFFSET {offset} APP_RANGES {ranges})\n')
                result = subprocess.run(command, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("DIFT layout invalid", result.stderr)


if __name__ == "__main__":
    unittest.main()
