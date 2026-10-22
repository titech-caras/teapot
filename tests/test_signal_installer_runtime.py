"""Compile and execute the actual runtime signal-alias C tests in temporary builds."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

RUNTIME = Path(__file__).resolve().parents[1] / 'libcheckpoint'
ALIASES = ('__sysv_signal', 'sysv_signal', 'bsd_signal', 'ssignal', 'sigset')


class SignalInstallerRuntimeTests(unittest.TestCase):
    def run_checked(self, argv, timeout=180):
        result = subprocess.run([str(arg) for arg in argv], text=True, capture_output=True, timeout=timeout)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout

    def check_runtime(self, arch):
        tools = ['cmake', 'ctest', 'gcc', 'nm']
        if arch == 'riscv64':
            tools += ['riscv64-linux-gnu-gcc', 'riscv64-linux-gnu-nm', 'qemu-riscv64']
        missing = [name for name in tools if not shutil.which(name)]
        if missing:
            self.skipTest('runtime signal test tools unavailable: ' + ', '.join(missing))
        with tempfile.TemporaryDirectory() as temporary:
            build = Path(temporary)
            command = ['cmake', '-S', RUNTIME, '-B', build, '-DBUILD_TESTING=ON',
                       '-DCMAKE_BUILD_TYPE=Release', '-DTEAPOT_ENABLE_FAULT_TRAINING=OFF',
                       '-DTEAPOT_ENABLE_FAULT_PUBLISHING=OFF', '-DTEAPOT_BUILD_NESTED_RUNTIME=OFF']
            nm = 'nm'
            if arch == 'x64':
                command += ['-DCHECKPOINT_ARCH=x86_64', '-DTEAPOT_DIFT_LAYOUT=x64-la48-asan-new',
                            '-DTEAPOT_ENABLE_DIFT_RUNTIME=OFF']
            else:
                command += ['-DCMAKE_SYSTEM_NAME=Linux', '-DCMAKE_SYSTEM_PROCESSOR=riscv64',
                            '-DCHECKPOINT_ARCH=riscv64', '-DCMAKE_C_COMPILER=riscv64-linux-gnu-gcc',
                            '-DCMAKE_ASM_COMPILER=riscv64-linux-gnu-gcc',
                            '-DCMAKE_C_FLAGS=-march=rv64gc -mabi=lp64d',
                            '-DCMAKE_ASM_FLAGS=-march=rv64gc -mabi=lp64d',
                            '-DTEAPOT_DIFT_LAYOUT=riscv64-sv39', '-DTEAPOT_ENABLE_RISCV_FLOAT_STATE=ON',
                            '-DCMAKE_CROSSCOMPILING_EMULATOR=qemu-riscv64;-L;/usr/riscv64-linux-gnu']
                nm = 'riscv64-linux-gnu-nm'
            self.run_checked(command)
            self.run_checked(['cmake', '--build', build, '--target', 'checkpoint',
                              'checkpoint_signal_installers_test', '--parallel', '2'])
            self.run_checked(['ctest', '--test-dir', build, '-R', '^checkpoint_signal_installers$',
                              '--output-on-failure', '--timeout', '30'], timeout=45)
            archive = build / 'libcheckpoint.a'
            symbols = self.run_checked([nm, '-g', '--defined-only', archive])
            for alias in ALIASES:
                self.assertIn(alias + '__teapot_wrapper__', symbols)
            self.run_checked([sys.executable, '-B', RUNTIME / 'tools/runtime_exports.py',
                              '--manifest', RUNTIME / 'tools/runtime_exports.json',
                              '--nm', nm, '--archive', archive])
            contract = json.loads((build / 'libcheckpoint.contract.json').read_text())
            self.assertEqual(contract['runtime']['signal_installer_coverage'], 1)
            for name, value in (('attacker', 1), ('attacker_indirect', 4),
                                ('secret', 2), ('secret_indirect', 8)):
                self.assertEqual(contract['abi']['dift.tag.' + name], value)
            if arch == 'riscv64':
                self.assertTrue(contract['capabilities']['riscv64_float_state'])

    def test_native_runtime_alias_semantics_exports_and_contract(self):
        self.check_runtime('x64')

    def test_rv64gc_lp64d_alias_semantics_exports_and_contract(self):
        self.check_runtime('riscv64')


if __name__ == '__main__':
    unittest.main()
