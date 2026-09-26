"""Narrow, provenance-bound return contracts for AArch64 normalization.

Absence means unknown, not scalar. The producer accepts only DWARF-proved
64-bit pointer returns and records their original object identity through the
ordinary assembler/linker. Contracts are consumed before instrumentation.
"""
import hashlib
import json
import re

import gtirb


POINTER_RETURNS = 'teapotAArch64PointerReturnsV1'
SCHEMA = 'mapping<UUID,tuple<string,string>>'


def function_fingerprint(module, function):
    members = module.aux_data['functionBlocks'].data[function]
    entries = module.aux_data['functionEntries'].data[function]
    value = {'function': str(function), 'entries': sorted(str(b.uuid) for b in entries),
             'blocks': sorted((str(b.uuid), b.address, b.size, bytes(b.contents).hex()) for b in members)}
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def has_pointer_return_contract(module, function):
    auxiliary = module.aux_data.get(POINTER_RETURNS)
    if auxiliary is None:
        return False
    if module.isa != gtirb.Module.ISA.ARM64 or auxiliary.type_name != SCHEMA:
        raise ValueError('invalid architecture/schema for pointer-return ABI evidence')
    row = auxiliary.data.get(function)
    if row is None:
        return False
    if (not isinstance(row, (tuple, list)) or len(row) != 2 or
            any(not isinstance(s, str) or not re.fullmatch(r'[0-9a-f]{64}', s) for s in row)):
        raise ValueError('malformed pointer-return ABI evidence')
    if row[0] != function_fingerprint(module, function):
        raise ValueError('stale pointer-return ABI evidence for changed function')
    return True
