class RISCV64AssemblyMixin:
    @staticmethod
    def load_address(reg: str, symbol: str) -> str:
        return f"""
        lui {reg}, %hi({symbol})
        addi {reg}, {reg}, %lo({symbol})
    """

    @classmethod
    def add_constant_from_base(cls, dst_reg, base_reg, tmp_reg, value: int) -> str:
        if value == 0:
            return "" if dst_reg == base_reg else f"mv {dst_reg}, {base_reg}\n"
        if -2048 <= value <= 2047:
            return f"addi {dst_reg}, {base_reg}, {value}\n"
        if tmp_reg is None:
            raise ValueError("RISC-V add immediate is not encodable without a temporary register")
        return (
            f"li {tmp_reg}, {value}\n" +
            f"add {dst_reg}, {base_reg}, {tmp_reg}\n"
        )

    @classmethod
    def call_symbol(cls, symbol: str) -> str:
        return f"""
            {cls.load_address("ra", symbol)}
            jalr ra
        """

    @classmethod
    def jump_symbol(cls, symbol: str, reg: str) -> str:
        return f"""
            {cls.load_address(reg, symbol)}
            jr {reg}
        """
