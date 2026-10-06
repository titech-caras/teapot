import unittest
from dataclasses import replace

from teapot.modes import COMPONENT_FIXED, COMPONENT_FREE, MODES, ModeError, option_fields, validate_options
from teapot.pipeline import InstrumentationOptions

ISAS = ("x64", "aarch64", "riscv64")


class ModeTableTests(unittest.TestCase):
    def test_every_option_is_classified_for_components(self):
        # A new option must be put in one table on purpose.
        fields = option_fields(InstrumentationOptions)
        self.assertEqual(set(COMPONENT_FIXED) | COMPONENT_FREE, fields)
        self.assertFalse(set(COMPONENT_FIXED) & COMPONENT_FREE)

    def test_accepted_combinations(self):
        cases = [(isa, InstrumentationOptions()) for isa in ISAS]
        cases += [("aarch64", InstrumentationOptions(aarch64_tag_storage="mte")),
                  ("aarch64", InstrumentationOptions(target_identification="aarch64-bti-pac")),
                  ("aarch64", InstrumentationOptions(target_identification="aarch64-bti-pac",
                                                     aarch64_tag_storage="mte"))]
        for isa, options in cases:
            for component in (False, True):
                with self.subTest(isa=isa, options=options, component=component):
                    mode = validate_options(options, isa, component=component)
                    self.assertIs(mode, MODES[options.target_identification])
        # Disables/nesting may combine. Publishing separately requires active
        # checkpoints; it is not meaningful in the all-disables combination.
        loose = InstrumentationOptions(**{field: not value for field, value in InstrumentationOptions().__dict__.items()
                                          if isinstance(value, bool)})
        loose = replace(loose, enable_fault_publishing=False)
        self.assertIs(validate_options(loose, "x64"), MODES["software"])
        self.assertIs(validate_options(InstrumentationOptions(enable_fault_training=True,
            enable_fault_publishing=True), "x64"), MODES["software"])

    def test_refused_combinations_name_the_conflict_and_remedy(self):
        bti = InstrumentationOptions(target_identification="aarch64-bti-pac")
        cases = [
            ("x64", bti, False, "aarch64-bti-pac requires AArch64; this module is x64"),
            ("riscv64", bti, False, "requires AArch64; this module is RV64"),
            ("aarch64", replace(bti, enable_checkpoints=False), False,
             "aarch64-bti-pac requires checkpoints; drop --disable-checkpoints"),
            ("aarch64", replace(bti, enable_indirect_transform=False, enable_indirect_check=False), False,
             "requires target transformation, target checking; drop --disable-indirect-transform and "
             "--disable-indirect-check"),
            ("x64", InstrumentationOptions(aarch64_tag_storage="mte"), False,
             "--aarch64-tag-storage=mte is only valid for AArch64 modules"),
            ("riscv64", InstrumentationOptions(aarch64_tag_storage="mte"), False,
             "--aarch64-tag-storage=mte is only valid for AArch64 modules"),
            ("aarch64", InstrumentationOptions(aarch64_tag_storage="none"), False,
             "unknown tag storage 'none'; choose one of mte, shadow"),
            ("aarch64", InstrumentationOptions(target_identification="aarch64-bti"), False,
             "unknown target identification 'aarch64-bti'"),
            ("x64", InstrumentationOptions(enable_nested_speculation=True), True,
             "enable_nested_speculation \\(nested speculation is not supported; drop --enable-nested-speculation\\)"),
            ("x64", InstrumentationOptions(enable_dift=False, conservative_flags=True), True,
             "requires the default instrumentation: enable_dift \\(drop --disable-dift\\); "
             "conservative_flags \\(drop --conservative-flags\\)"),
        ]
        for isa, options, component, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ModeError, message):
                    validate_options(options, isa, component=component)
        for field, remedy in COMPONENT_FIXED.items():
            default = getattr(InstrumentationOptions(), field)
            changed = {bool: lambda value: not value, str: lambda value: "sse",
                       type(None): lambda value: "app"}[type(default)](default)
            with self.subTest(field=field):
                with self.assertRaisesRegex(ModeError, field):
                    validate_options(replace(InstrumentationOptions(), **{field: changed}), "x64", component=True)


if __name__ == "__main__":
    unittest.main()
