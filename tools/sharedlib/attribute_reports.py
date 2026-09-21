"""Normalize x64 reports by input/function/report-call ordinal, retaining raw data.

The ordinal identifies a static report-call instruction of one gadget kind in
its transient function. This is stronger than total counts but not a proof of
instruction-level source equivalence. Memory addresses are deliberately kept as
raw evidence, not compared as stable identities across layouts.
"""
import bisect
from collections import Counter, defaultdict
import difflib
import json
from pathlib import Path
import re
import subprocess

from compare_corpus import WORK, ROOT, REPORT


OUT = WORK / 'artifacts/report-attribution-v2'
OLD_BIN = ROOT / 'workers/baseline-libhtp-20260921/full-links/x64-la48-asan-new-clean/test_fuzz'
NEW_BIN = WORK / 'artifacts/libhtp/instrumented-v2/monolith.instrumented'
OLD_LOG = ROOT / 'workers/root/baseline-20260921/libhtp-sweep-x64-clean/x64-la48-asan-new'
NEW_LOG = WORK / 'artifacts/libhtp/instrumented-v2-corpus'


def symbols(binary):
    result = []
    for line in subprocess.check_output(['nm', '-n', '--defined-only', str(binary)], text=True).splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[1] in 'tT':
            result.append((int(fields[0], 16), fields[2]))
    return result


def locate(anchors, address):
    index = bisect.bisect_right(anchors, (address, '\uffff')) - 1
    if index < 0:
        raise AssertionError(hex(address))
    return anchors[index][1]


def site_map(binary, origins, label):
    anchors = sorted((address, name[:-10]) for address, name in symbols(binary)
                     if name.endswith('__teapot__') and name[:-10] in origins)
    normal = sorted((address, name) for address, name in symbols(binary) if name in origins)
    disassembly = subprocess.check_output(['objdump', '-d', '-j', '.teapot_transient', str(binary)], text=True)
    (OUT / (label + '.transient.disassembly')).write_text(disassembly)
    counters, sites = Counter(), {}
    for line in disassembly.splitlines():
        match = re.match(r'\s*([0-9a-f]+):.*\bcall\s+[0-9a-f]+ <report_gadget_(KASPER_\w+)>', line)
        if not match:
            continue
        address, kind = int(match[1], 16), match[2]
        function = locate(anchors, address)
        key = function, kind
        ordinal = counters[key]
        counters[key] += 1
        sites[address] = (function, kind, ordinal)
    return sites, normal, counters


def read_reports(log, sites, normal):
    result, raw = Counter(), []
    for line in log.read_bytes().splitlines(keepends=True):
        match = REPORT.fullmatch(line)
        if not match:
            continue
        address = int(match[3], 16)
        site = sites[address]
        assert site[1] == match[2].decode()
        checkpoint_addresses = [int(c, 16) for c in match[7].decode().split(', ') if c]
        checkpoint_functions = tuple(locate(normal, c) for c in checkpoint_addresses)
        tag, counter = int(match[5], 16), int(match[6])
        key = site + (tag, counter, checkpoint_functions)
        result[key] += 1
        raw.append({'address': hex(address), 'site': site, 'tag': tag,
                    'instruction_counter': counter, 'checkpoint_functions': checkpoint_functions,
                    'memory_address': match[4].decode(),
                    'checkpoint_addresses': [hex(c) for c in checkpoint_addresses]})
    return result, raw


if __name__ == '__main__':
    OUT.mkdir(parents=True, exist_ok=False)
    origins = {}
    for binary, module in ((WORK / 'inputs/libhtp/test_fuzz', 'executable'),
                            (WORK / 'inputs/libhtp/libhtp.so.2', 'selected-libhtp')):
        for address, name in symbols(binary):
            origins[name] = {'module': module, 'input_address': hex(address), 'binary': str(binary)}
    old_sites, old_normal, old_counts = site_map(OLD_BIN, origins, 'static-baseline')
    new_sites, new_normal, new_counts = site_map(NEW_BIN, origins, 'converted-shared')
    cases, observed = [], {}
    counter_deltas = Counter()
    for case in sorted(p for p in NEW_LOG.iterdir() if p.is_dir()):
        old, old_raw = read_reports(OLD_LOG / case.name / 'stderr', old_sites, old_normal)
        new, new_raw = read_reports(case / 'stderr', new_sites, new_normal)
        old_sites_only, new_sites_only = defaultdict(list), defaultdict(list)
        for rows, grouped in ((old_raw, old_sites_only), (new_raw, new_sites_only)):
            for row in rows:
                grouped[tuple(row['site']) + (row['tag'], tuple(row['checkpoint_functions']))].append(row['instruction_counter'])
        site_match = {k: len(v) for k, v in old_sites_only.items()} == {k: len(v) for k, v in new_sites_only.items()}
        if site_match:
            for key, counters in old_sites_only.items():
                for previous, current in zip(sorted(counters), sorted(new_sites_only[key])):
                    counter_deltas[current-previous] += 1
        for row in new_raw:
            key = tuple(row['site'])
            observed.setdefault(key, set()).add(row['address'])
        cases.append({'input': case.name, 'matched': old == new,
                      'matched_sites_tags_checkpoint_functions': site_match,
                      'baseline_reports': old_raw, 'converted_reports': new_raw,
                      'baseline_only': [{'identity': k, 'count': v} for k, v in (old-new).items()],
                      'converted_only': [{'identity': k, 'count': v} for k, v in (new-old).items()]})
    site_rows = []
    for (function, kind, ordinal), addresses in sorted(observed.items()):
        origin = origins[function]
        source = subprocess.check_output(['addr2line', '-e', origin['binary'], '-f', '-C',
                                          origin['input_address']], text=True).splitlines()
        site_rows.append({'function': function, 'kind': kind, 'report_call_ordinal': ordinal,
                          'converted_addresses': sorted(addresses), 'origin': origin,
                          'function_entry_source': source,
                          'baseline_static_site_count': old_counts[(function, kind)],
                          'converted_static_site_count': new_counts[(function, kind)]})
    ordinary = [ROOT / 'workers/baseline-libhtp-20260921/libhtp-src/test/test_fuzz',
                WORK / 'artifacts/libhtp/v3/monolith']
    function = 'htp_normalize_uri_path_inplace'
    normalized = []
    for label, binary in zip(('static-baseline', 'converted-shared'), ordinary):
        disassembly = subprocess.check_output(['objdump', '-d', '--no-show-raw-insn',
            '--disassemble=' + function, str(binary)], text=True)
        (OUT / (label + '.ordinary-normalizer.disassembly')).write_text(disassembly)
        instructions = []
        for line in disassembly.splitlines():
            match = re.match(r'\s*[0-9a-f]+:\s*(.*)', line)
            if match:
                instruction = re.sub(r'[0-9a-f]+ <', '<', match[1])
                instruction = re.sub(r'-?0x[0-9a-f]+\(%rip\)', 'DISP(%rip)', instruction)
                instructions.append(re.sub(r'\+0x[0-9a-f]+>', '+LOCAL>', instruction))
        normalized.append(instructions)
    (OUT / 'ordinary-normalizer.diff').write_text('\n'.join(difflib.unified_diff(
        normalized[0], normalized[1], fromfile='original-static', tofile='converted-shared')) + '\n')
    result = {'inputs': len(cases), 'matched_including_instruction_counters': sum(c['matched'] for c in cases),
              'matched_sites_tags_checkpoint_functions': sum(c['matched_sites_tags_checkpoint_functions'] for c in cases),
              'counter_delta_histogram': dict(counter_deltas),
              'observed_sites': site_rows, 'cases': cases,
              'normalization': 'function + gadget kind + per-function/kind report-call ordinal + tag + instruction counter + checkpoint function sequence',
              'counter_difference': '86/810 reports are +3 after a reachable four-byte NOP was reprinted as four one-byte NOPs in htp_normalize_uri_path_inplace. The fresh lift counts 4 instructions instead of 1. See retained ordinary disassemblies/diff. No assembly text filter was applied.',
              'limits': ['Source lines are function entry attribution, not exact source gadget lines.',
                         'Original machine-instruction equivalence is not proved by report-call ordinal.',
                         'Memory and checkpoint raw addresses differ with layout and are retained but not compared.',
                         'Counter differences can change speculation coverage near ROB=250 on untested paths; these are not fully report-equivalent runs.',
                         'Single-run evidence; not a proof over untested inputs or architectures.']}
    (OUT / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: v for k, v in result.items() if k not in ('cases', 'observed_sites')}, indent=2))
    print('Observed sites:', len(site_rows))
