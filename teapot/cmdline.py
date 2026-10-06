import argparse
import ctypes
import gc
import logging
import sys

import gtirb

from teapot.configs.runtime import ASAN_TAG_STORAGES, ASAN_TAG_STORAGE_SHADOW
from teapot.pipeline import InstrumentationOptions, TeapotPipeline
from teapot.preprocess.runtime_names import RuntimeNameError
from teapot.runtime_contract import RuntimeContractError, load_runtime_contract
from teapot.utils.serialization import compact_for_pprinter, save_protobuf_ordered


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--adaptive-fault-precheck", action="store_true",
                        help="Emit validated scalar fault prechecks (requires an ISA-matched publishing runtime; "
                             "single-threaded only). TEAPOT_FAULT_ADAPTATION=0 disables activation at startup.")
    parser.add_argument('--force-checkpoint-df', action='store_true',
                        help='Save DF at every x64 checkpoint instead of selecting DF-sensitive sites')
    parser.add_argument('--x64-vector-state', choices=('auto', 'xmm0-7', 'sse', 'avx', 'full'),
                        default='auto', help=('Checkpoint vector state: auto uses per-site liveness '
                                              '(unknown means full); xmm0-7/sse/avx are unsafe '
                                              'overrides that can corrupt program results'))
    parser.add_argument("--conservative-flags", action="store_true",
                        help="Keep the condition flags live at every instruction instead of dead across calls and returns.")
    parser.add_argument("--target-identification", choices=("software", "aarch64-bti-pac"),
                        default="software", help="The experimental BTI+PAC mode requires its matching runtime and linker script.")
    parser.add_argument("input", nargs="?")
    parser.add_argument("output", nargs="?")
    parser.add_argument(
        "--debug-source", metavar="ELF",
        help=("Preserve source lines from the original ELF's DWARF (off by default). "
              "After printing, run python -m teapot.debug_lines IR RAW.S OUTPUT.S."),
    )
    parser.add_argument(
        "--runtime-contract", metavar="JSON", required=True,
        help=("The lib<archive>.contract.json beside the libcheckpoint archive this rewrite will be "
              "linked with (libcheckpoint_nested.contract.json for --enable-nested-speculation). "
              "Teapot refuses a runtime whose layout it does not emit and takes the DIFT layout from it, "
              "and its coverage mode: speculative coverage guards are pushed only for a runtime built "
              "for a fuzzer (-DTEAPOT_ENABLE_COVERAGE=ON)."),
    )
    parser.add_argument(
        "--dift-layout",
        help="Optional: the DIFT layout profile the runtime must have been built with.",
    )
    parser.add_argument(
        "--disable-dift",
        action="store_true",
        help="Skip DIFT propagation and DIFT external-call handling.",
    )
    parser.add_argument(
        "--transient-dift", choices=("lazy", "eager"), default="lazy",
        help="Flush transient LLVM tag replay before readers (default), or after each instruction's effects.",
    )
    parser.add_argument(
        "--disable-asan",
        action="store_true",
        help="Skip ASan stack poisoning instrumentation.",
    )
    parser.add_argument(
        "--aarch64-tag-storage",
        choices=ASAN_TAG_STORAGES,
        default=ASAN_TAG_STORAGE_SHADOW,
        help=(
            "AArch64 storage backend for Teapot ASan-style tags. "
            "The mte backend uses MTE allocation tags as software-read metadata."
        ),
    )
    parser.add_argument(
        "--disable-gadgets",
        action="store_true",
        help="Skip transient gadget detection policies and coverage guards (even for a coverage runtime).",
    )
    parser.add_argument(
        "--disable-mem-operand-gadgets",
        action="store_true",
        help="Skip transient memory-operand gadget policies.",
    )
    parser.add_argument(
        "--disable-port-gadgets",
        action="store_true",
        help="Skip transient port-contention gadget policies.",
    )
    parser.add_argument(
        "--disable-gadget-asan-check",
        action="store_true",
        help="Skip the transient memory-operand gadget policy ASan subcheck.",
    )
    parser.add_argument(
        "--disable-memlog",
        action="store_true",
        help="Skip transient memory logging.",
    )
    parser.add_argument(
        "--disable-checkpoints",
        action="store_true",
        help="Skip text checkpoint insertion and transient restore points.",
    )
    parser.add_argument(
        "--enable-nested-speculation",
        action="store_true",
        help=(
            "Insert checkpoints inside the transient copy as well. "
            "The instrumented binary must link libcheckpoint target checkpoint_nested."
        ),
    )
    parser.add_argument(
        "--disable-indirect-transform",
        action="store_true",
        help="Skip text indirect-branch target markers.",
    )
    parser.add_argument(
        "--disable-indirect-check",
        action="store_true",
        help="Skip transient indirect-branch destination checks.",
    )
    parser.add_argument(
        "--disable-aarch64-relax",
        action="store_true",
        help="Skip the AArch64 conditional-branch relaxation pass.",
    )
    parser.add_argument(
        "--rewrite-progress",
        action="store_true",
        help="Log coarse gtirb-rewriting phase and large-loop progress.",
    )
    parser.add_argument(
        "--compact-output",
        action="store_true",
        help=(
            "Before serialization, discard CFG edges and code-only symbolic "
            "expression widths that the GTIRB pretty-printer does not consume."
        ),
    )
    args = parser.parse_args()

    if args.input is None or args.output is None:
        parser.error("input and output are required")
    try:
        runtime_contract = load_runtime_contract(args.runtime_contract)
    except RuntimeContractError as error:
        sys.exit(f"teapot: {error}")
    if args.rewrite_progress:
        logging.basicConfig(
            format="%(asctime)s [%(name)s] %(message)s",
            datefmt="%H:%M:%S",
        )
        logging.getLogger("gtirb_rewriting").setLevel(logging.INFO)

    ir = gtirb.IR.load_protobuf(args.input)
    options = InstrumentationOptions(
        enable_dift=not args.disable_dift,
        eager_transient_dift=args.transient_dift == "eager",
        enable_asan=not args.disable_asan,
        enable_gadgets=not args.disable_gadgets,
        enable_memlog=not args.disable_memlog,
        enable_checkpoints=not args.disable_checkpoints,
        enable_indirect_transform=not args.disable_indirect_transform,
        enable_indirect_check=not args.disable_indirect_check,
        enable_conditional_branch_relax=(not args.disable_aarch64_relax or
                                         ir.modules[0].isa != gtirb.Module.ISA.ARM64),
        enable_mem_operand_gadgets=not args.disable_mem_operand_gadgets,
        enable_port_gadgets=not args.disable_port_gadgets,
        enable_gadget_asan_check=not args.disable_gadget_asan_check,
        enable_nested_speculation=args.enable_nested_speculation,
        aarch64_tag_storage=args.aarch64_tag_storage,
        target_identification=args.target_identification,
        debug_source=args.debug_source,
        conservative_flags=args.conservative_flags,
        force_checkpoint_df=args.force_checkpoint_df,
        x64_vector_state=args.x64_vector_state,
        enable_fault_training=args.adaptive_fault_precheck,
        enable_fault_publishing=args.adaptive_fault_precheck,
    )
    pipeline = TeapotPipeline(ir, args.dift_layout, options, runtime_contract=runtime_contract)
    try:
        pipeline.run()
    except (RuntimeContractError, RuntimeNameError) as error:
        sys.exit(f"teapot: {error}")
    del pipeline

    # Protobuf serialization constructs a second representation of the IR.
    # Return memory released by the rewrite passes before building it.
    print("[teapot] begin serialization cleanup", flush=True)
    if args.compact_output:
        compact_stats = compact_for_pprinter(ir)
        print(
            "[teapot] compact output "
            f"cfg_edges_removed={compact_stats.cfg_edges_removed} "
            f"symbolic_sizes_before={compact_stats.symbolic_sizes_before} "
            f"symbolic_sizes_after={compact_stats.symbolic_sizes_after} "
            f"code_only_sizes_removed={compact_stats.code_only_sizes_removed}",
            flush=True,
        )
    gc.collect()
    try:
        malloc_trim = ctypes.CDLL(None).malloc_trim
    except (AttributeError, OSError):
        pass
    else:
        malloc_trim.argtypes = (ctypes.c_size_t,)
        malloc_trim.restype = ctypes.c_int
        malloc_trim(0)
    print("[teapot] end serialization cleanup", flush=True)

    print("[teapot] begin serialization", flush=True)
    save_protobuf_ordered(ir, args.output)
    print("[teapot] end serialization", flush=True)
    if any("teapotFaultRiscAssemblyScopes" in module.aux_data for module in ir.modules):
        from teapot.fault_risc_assembly import fault_risc_assembler_flags
        flags = sorted({flag for module in ir.modules for flag in fault_risc_assembler_flags(module)})
        print("[teapot] RV adaptive output requires: python -m teapot.fault_risc_assembly "
              "IR RAW.S OUTPUT.S before assembly (or the teapot.debug_lines CLI when used). "
              "Assemble with " + " ".join(flags) + "; link with -Wl,-z,separate-code. "
              "An unprepared listing is unsupported; final ELF validation is still required.", flush=True)


if __name__ == "__main__":
    main()
