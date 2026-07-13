import argparse

import gtirb

from teapot.configs.runtime import ASAN_TAG_STORAGES, ASAN_TAG_STORAGE_SHADOW
from teapot.datacls.dift_layout import LAYOUTS, layout_names_for_arch
from teapot.pipeline import InstrumentationOptions, TeapotPipeline


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", nargs="?")
    parser.add_argument("output", nargs="?")
    parser.add_argument(
        "--dift-layout",
        choices=sorted(LAYOUTS),
        help="Compile-time DIFT address-space layout profile. The runtime library must be built with the same profile.",
    )
    parser.add_argument(
        "--list-dift-layouts",
        action="store_true",
        help="Print DIFT layout profiles and exit.",
    )
    parser.add_argument(
        "--disable-dift",
        action="store_true",
        help="Skip DIFT propagation and DIFT external-call handling.",
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
        help="Skip transient gadget detection policies and coverage guards.",
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
    args = parser.parse_args()

    if args.list_dift_layouts:
        for arch_name in ("x64", "aarch64", "riscv64"):
            print(f"{arch_name}: {', '.join(sorted(layout_names_for_arch(arch_name)))}")
        return
    if args.input is None or args.output is None:
        parser.error("input and output are required")

    ir = gtirb.IR.load_protobuf(args.input)
    options = InstrumentationOptions(
        enable_dift=not args.disable_dift,
        enable_asan=not args.disable_asan,
        enable_gadgets=not args.disable_gadgets,
        enable_memlog=not args.disable_memlog,
        enable_checkpoints=not args.disable_checkpoints,
        enable_indirect_transform=not args.disable_indirect_transform,
        enable_indirect_check=not args.disable_indirect_check,
        enable_conditional_branch_relax=not args.disable_aarch64_relax,
        enable_mem_operand_gadgets=not args.disable_mem_operand_gadgets,
        enable_port_gadgets=not args.disable_port_gadgets,
        enable_gadget_asan_check=not args.disable_gadget_asan_check,
        enable_nested_speculation=args.enable_nested_speculation,
        aarch64_tag_storage=args.aarch64_tag_storage,
    )
    TeapotPipeline(ir, args.dift_layout, options).run()
    ir.save_protobuf(args.output)


if __name__ == "__main__":
    main()
