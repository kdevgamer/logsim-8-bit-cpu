INSTRUCTION_SET = {
    "IN":  0x0,
    "Out": 0x1,
    "Mov": 0x2,
    "Swp": 0x3,
    "Add": 0x4,
    "Sub": 0x5,
    "And": 0x6,
    "Or":  0x7,
    "Xor": 0x8,
    "Not": 0x9,
    "Jmp": 0xA,
    "Jz":  0xB,
    "Nop": 0xC,
    "RamW": 0xD,
    "RamR": 0xE
}

NOP_BYTE = 0xC0
MEMORY_SIZE = 256

def assemble(lines):
    bytecode = []

    for line in lines:
        line = line.split(";")[0].strip()
        if not line:
            continue

        parts = line.split()
        mnemonic = parts[0]
        opcode = INSTRUCTION_SET.get(mnemonic)
        if opcode is None:
            raise ValueError(f"Unknown instruction: {mnemonic}")

        operand = 0
        if mnemonic in ["Mov", "Jmp", "Jz"]:
            if len(parts) < 2:
                raise ValueError(f"{mnemonic} requires an operand.")
            operand = int(parts[1], 0) & 0x0F
        elif mnemonic == "Swp":
            bytecode.append((opcode << 4) | 0x0)
            bytecode.append(NOP_BYTE)
            continue
        elif mnemonic == "IN":
            bytecode.append((opcode << 4) | 0x0)
            bytecode.append(0x00)
            continue
        elif mnemonic == "RamW" or mnemonic == "RamR":
            bytecode.append((opcode << 4) | 0x0)
            bytecode.append(NOP_BYTE)
            continue

        bytecode.append((opcode << 4) | operand)

    # Fill remaining memory with NOPs
    while len(bytecode) < MEMORY_SIZE:
        bytecode.append(NOP_BYTE)

    return bytecode

def assemble_file(input_filename, output_filename="output.bin"):
    with open(input_filename, "r") as f:
        lines = f.readlines()

    bytecode = assemble(lines)

    with open(output_filename, "wb") as f:
        f.write(bytearray(bytecode))

    print(f"✅ Assembled to '{output_filename}' ({len(bytecode)} bytes, filled with NOPs)")

# Example usage
if __name__ == "__main__":
    assemble_file("program.asm", "output.bin")
