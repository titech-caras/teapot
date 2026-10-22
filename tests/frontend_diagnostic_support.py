"""Small genuine lift/diagnostic records for component-cache unit fixtures."""
from pathlib import Path

import gtirb

from tools.sharedlib import convert as converter


def lift_record(directory, item, policy=False, diagnostics='', module=None):
    module = module or gtirb.Module(name='fixture', isa=gtirb.Module.ISA.X64,
                                    file_format=gtirb.Module.FileFormat.ELF)
    ir = module.ir or gtirb.IR(modules=[module])
    ir.save_protobuf(directory / 'lift.gtirb')
    lift = directory / 'lift'
    lift.mkdir(exist_ok=True)
    command = ['ddisasm', item['path'], '--ir', str(directory / 'lift.gtirb'), '-j', '1']
    if policy:
        command.append('--allow-ambiguous-data-pointers')
    converter.dump(lift / 'command.json', command)
    (lift / 'stderr').write_text(diagnostics)
    (lift / 'stdout').write_text('')
    converter.dump(lift / 'result.json', {'exit': 0})
    converter.record_frontend_diagnostics(module, item, directory, policy)
    return module


def component_frontend_fields(directory, item, policy=False):
    lift_record(directory, item, policy)
    files = {name: converter.sha(directory / name) for name in converter.FRONTEND_DIAGNOSTIC_FILES}
    return {'allow_ambiguous_data_pointers': policy,
            'allow_runtime_symbol_lookup': item.get('allow_runtime_symbol_lookup', False),
            'pointer_inference': 'unproven heuristic' if policy else 'strict',
            'frontend_diagnostics_sha256': files['frontend-diagnostics.json'], 'files': files}
