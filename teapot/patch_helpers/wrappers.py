from typing import Optional

from teapot.config import SYMBOL_SUFFIX


def conditional_patch_wrapper(asm: str, conditional: Optional[str], *,
                              label_key: str = "conditional",
                              doit_label_name: Optional[str] = None,
                              skip_label_name: Optional[str] = None,
                              insert_skip_label: bool = True):
    if conditional is None:
        return asm

    if doit_label_name is None:
        doit_label_name = f".L__{label_key}_doit" + SYMBOL_SUFFIX

    if skip_label_name is None:
        skip_label_name = f".L__{label_key}_skip" + SYMBOL_SUFFIX

    wrapped_asm = f"""
            j{conditional} {doit_label_name}
            jmp {skip_label_name}
        {doit_label_name}:
            {asm}
    """

    if insert_skip_label:
        wrapped_asm += f"""
            {skip_label_name}:
                nop
        """

    return wrapped_asm