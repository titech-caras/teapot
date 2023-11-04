from typing import Optional
from gtirb_rewriting import Register, RewritingContext

from NaHCO3.config import ASAN_SHADOW_OFFSET


def asan_check_snippet(addr_reg: Register, access_size: int, check_ok_label: str, *,
                       r1: Register, r2: Optional[Register] = None):
    r1_shadow_subreg = r1.sizes["8l" if access_size <= 8 else str(access_size)]

    detailed_check_snippet = ""
    if access_size < 8:
        assert r2 is not None
        detailed_check_snippet += f"""
            mov {r2:8l}, {addr_reg:8l}
            and {r2:8l}, 7 
        """

        if access_size > 1:
            detailed_check_snippet += f"add {r2:8l}, {access_size - 1}\n"

        detailed_check_snippet += f"""
            cmp {r2:8l}, {r1_shadow_subreg}
            jnb {check_ok_label}
        """

    return f"""
        mov {r1}, {addr_reg}
        shr {r1}, 3
        mov {r1_shadow_subreg}, [{r1}+{ASAN_SHADOW_OFFSET}]
        test {r1_shadow_subreg}, {r1_shadow_subreg}
        je {check_ok_label}
        {detailed_check_snippet}
    """