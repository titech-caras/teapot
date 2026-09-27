"""The Arm-specific CLI switch must not break x86 rel8-only branches."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import gtirb

from teapot import cmdline
from teapot.arch.x64.architecture import X64Architecture


class RelaxationOptionTests(unittest.TestCase):
    def options_for(self, ir):
        with patch('sys.argv', ['teapot', 'input', 'output', '--disable-aarch64-relax']), \
                patch.object(gtirb.IR, 'load_protobuf', return_value=ir), \
                patch.object(gtirb.IR, 'save_protobuf'), \
                patch.object(cmdline, 'TeapotPipeline') as pipeline:
            cmdline.main()
            return pipeline.call_args.args[2]

    def test_arm_only_cli_switch(self):
        for isa in (gtirb.Module.ISA.ARM64, gtirb.Module.ISA.X64):
            with self.subTest(isa=isa):
                ir = gtirb.IR(modules=[gtirb.Module(name='probe', isa=isa)])
                self.assertEqual(self.options_for(ir).enable_conditional_branch_relax,
                                 isa != gtirb.Module.ISA.ARM64)

    @unittest.skipUnless(shutil.which('gtirb-pprinter') and shutil.which('gcc'),
                         'printer/compiler unavailable')
    def test_x64_long_jrcxz_still_assembles_with_arm_switch(self):
        module = gtirb.Module(name='jrcxz', isa=gtirb.Module.ISA.X64,
                             file_format=gtirb.Module.FileFormat.ELF,
                             byte_order=gtirb.Module.ByteOrder.Little)
        ir = gtirb.IR(modules=[module])
        section = gtirb.Section(name='.text', module=module,
            flags={gtirb.Section.Flag.Readable, gtirb.Section.Flag.Executable})
        interval = gtirb.ByteInterval(address=0x1000, section=section,
                                      contents=b'\xe3\x00' + b'\x90' * 300 + b'\xc3')
        branch = gtirb.CodeBlock(size=2, byte_interval=interval)
        fallthrough = gtirb.CodeBlock(size=300, offset=2, byte_interval=interval)
        target = gtirb.CodeBlock(size=1, offset=302, byte_interval=interval)
        symbol = gtirb.Symbol(name='far_target', payload=target, module=module)
        interval.symbolic_expressions[1] = gtirb.SymAddrConst(0, symbol)
        module.aux_data['symbolicExpressionSizes'] = gtirb.AuxData(
            {gtirb.Offset(interval, 1): 1}, 'mapping<Offset,uint64_t>')
        for name, schema in (('functionEntries', 'mapping<UUID,set<UUID>>'),
                             ('functionBlocks', 'mapping<UUID,set<UUID>>'),
                             ('functionNames', 'mapping<UUID,UUID>'),
                             ('elfSymbolInfo', 'mapping<UUID,tuple<uint64_t,string,string,string,uint64_t>>')):
            module.aux_data[name] = gtirb.AuxData({}, schema)
        module.aux_data['sectionProperties'] = gtirb.AuxData(
            {section: (1, 6)}, 'mapping<UUID,tuple<uint64_t,uint64_t>>')
        ir.cfg.update({gtirb.Edge(branch, target, gtirb.Edge.Label(
            type=gtirb.Edge.Type.Branch, conditional=True, direct=True)),
            gtirb.Edge(branch, fallthrough, gtirb.Edge.Label(type=gtirb.Edge.Type.Fallthrough))})
        options = self.options_for(ir)
        self.assertTrue(options.enable_conditional_branch_relax)
        if options.enable_conditional_branch_relax:
            X64Architecture().relax_conditional_branches(module)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ir.save_protobuf(root / 'output.gtirb')
            printed = subprocess.run(['gtirb-pprinter', '--ir', str(root / 'output.gtirb'),
                                      '--asm', str(root / 'output.S'), '--syntax', 'intel'],
                                     capture_output=True)
            self.assertEqual(printed.returncode, 0, printed.stderr.decode())
            result = subprocess.run(['gcc', '-c', str(root / 'output.S'),
                                     '-o', str(root / 'output.o')], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
