
import string

part1 = bytes.fromhex("F3 0F 1E FA 55 48 89 E5 48 89 7D E8 48 8B 45 E8 0F B6 40")
part2 = bytes.fromhex("83 F0 01 84 C0 74 53 C7 45 FC 00 00 00 00 EB 3C 48 8B 55 E8 8B 45 FC 48 98 0F B6 34 02 48 8B 45 E8 48 8B 50")
part3 = bytes.fromhex("8B 45 FC 83 E0 07 C1 E0 03 89 C1 48 D3 EA 48 89 D0 31 F0 F7 D0 89 C1 48 8B 55 E8 8B 45 FC 48 98 88 0C 02 83 45 FC 01 83 7D FC")
part4 = bytes.fromhex("7E BE 48 8B 45 E8 C6 40")
part5 = bytes.fromhex("01 48 8B 45 E8 5D C3")

for addr in Functions():
    func = ida_funcs.get_func(addr)
    data = get_bytes(func.start_ea, func.end_ea - func.start_ea)    

    if data[:0x13] != part1: continue
    if data[0x14:0x38] != part2: continue
    if data[0x39:0x63] != part3: continue
    if data[0x64:0x6C] != part4: continue
    if data[0x6D:] != part5: continue

    size = data[0x13]

    addr = list(XrefsTo(addr))[0].frm
    for i in range(10):
        addr = prev_head(addr)

        mnem = print_insn_mnem(addr)
        opnd0 = print_operand(addr, 0)
        if mnem == "lea" and opnd0 == "rdi":
            ptr = list(XrefsFrom(addr))[1].to
            break
    else:
        raise RuntimeError("Couldn't find string")
    
    data = get_bytes(ptr, size)[:-1]
    mask = get_bytes((ptr + size + 7) & ~7, 8)
    decrypted = bytes([data[i] ^ mask[i % len(mask)] ^ 0xFF for i in range(len(data))])

    print(f"0x{ptr:X}: {decrypted}")

    try:
        decoded = decrypted.decode()
    except UnicodeDecodeError:
        decoded = decrypted.hex()    
    
    name = "s_"
    for char in decoded:
        if char in string.ascii_letters + string.digits:
            name += char
        else:
            name += "_"
    
    set_name(ptr, name)
    set_cmt(ptr, decoded, True)
