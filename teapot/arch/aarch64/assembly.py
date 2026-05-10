class AArch64AssemblyMixin:
    @staticmethod
    def load_address(reg: str, symbol: str) -> str:
        return f"""
        adrp {reg}, {symbol}
        add {reg}, {reg}, :lo12:{symbol}
    """

    @staticmethod
    def add_sub_immediate(op: str, dst_reg, base_reg, value: int):
        if value < 0:
            raise ValueError("AArch64 add/sub immediate value must be non-negative")
        if value <= 4095:
            return f"{op} {dst_reg}, {base_reg}, #{value}"
        if value % 4096 == 0 and value // 4096 <= 4095:
            return f"{op} {dst_reg}, {base_reg}, #{value // 4096}, lsl #12"
        return None

    @staticmethod
    def mov_u64(reg, value: int) -> str:
        segments = [(value >> shift) & 0xffff for shift in (0, 16, 32, 48)]
        lines = [f"mov {reg}, #{segments[0]}"]
        for idx, segment in enumerate(segments[1:], start=1):
            if segment:
                lines.append(f"movk {reg}, #{segment}, lsl #{idx * 16}")
        return "\n".join(lines) + "\n"

    @staticmethod
    def mov_w_imm32(reg: str, value: int) -> str:
        reg = f"{reg}"
        lo = value & 0xffff
        hi = (value >> 16) & 0xffff
        lines = [f"mov {reg}, #{lo}"]
        if hi:
            lines.append(f"movk {reg}, #{hi}, lsl #16")
        return "\n".join(lines) + "\n"

    def add_sub_constant_from_base(self, op: str, dst_reg, base_reg, tmp_reg, value: int) -> str:
        encoded = self.add_sub_immediate(op, dst_reg, base_reg, value)
        if encoded is not None:
            return encoded + "\n"
        if tmp_reg is None:
            raise ValueError(f"AArch64 {op} immediate is not encodable without a temporary register")
        return (
            self.mov_u64(tmp_reg, value) +
            f"{op} {dst_reg}, {base_reg}, {tmp_reg}\n"
        )
