
from Crypto.Cipher import AES

import galois
import numpy
import os
import shutil
import struct
import zlib


class WUHBUnpacker:
    _data: bytes

    _dir_table_ofs: int
    _file_table_ofs: int
    _file_partition_ofs: int

    def __init__(self, data):
        self._data = data

        self._dir_table_ofs = 0
        self._file_table_ofs = 0
        self._file_partition_ofs = 0
    
    def unpack(self, target: str) -> None:
        header_magic, header_size, dir_hash_table_ofs, dir_hash_table_size, \
            dir_table_ofs, dir_table_size, file_hash_table_ofs, \
            file_hash_table_size, file_table_ofs, file_table_size, \
            file_partition_ofs = struct.unpack_from(">4sIQQQQQQQQQ", self._data)
        
        assert header_magic == b"WUHB"
        assert header_size == 0x50

        self._dir_table_ofs = dir_table_ofs
        self._file_table_ofs = file_table_ofs
        self._file_partition_ofs = file_partition_ofs

        self._unpack_directory(0, target)
    
    def _unpack_directory(self, offset: int, base: str) -> None:
        offset += self._dir_table_ofs

        parent, sibling, child, file, hash, name_size = struct.unpack_from(
            ">IiiiiI", self._data, offset
        )
        offset += 0x18

        name = self._data[offset : offset + name_size].decode()
        os.mkdir(os.path.join(base, name))

        if file != -1:
            self._unpack_file(file, os.path.join(base, name))
        
        if child != -1:
            self._unpack_directory(child, os.path.join(base, name))

        if sibling != -1:
            self._unpack_directory(sibling, base)
    
    def _unpack_file(self, offset: int, base: str) -> None:
        offset += self._file_table_ofs

        parent, sibling, dataoffs, size, hash, name_size = struct.unpack_from(
            ">IiQQiI", self._data, offset
        )
        offset += 0x20

        name = self._data[offset : offset + name_size].decode()

        dataoffs += self._file_partition_ofs

        data = self._data[dataoffs : dataoffs + size]
        with open(os.path.join(base, name), "wb") as f:
            f.write(data)
        
        if sibling != -1:
            self._unpack_file(sibling, base)


def to_bits(value: int) -> list[int]:
    bits = []
    for i in range(128):
        bits.append((value >> (127 - i)) & 1)
    return bits

def solve_matrix(matrix: list[int], target: int) -> int:
    field = galois.GF(2)

    matrix = field([to_bits(row) for row in matrix])
    target = field(to_bits(target))

    solution = numpy.linalg.solve(matrix, target)

    value = 0
    for i in range(128):
        value |= int(solution[i]) << (127 - i)
    return value

def main() -> None:
    with open("challenge.wuhb", "rb") as f:
        data = f.read()
    
    if os.path.isdir("challenge"):
        shutil.rmtree("challenge")
    
    unpacker = WUHBUnpacker(data)
    unpacker.unpack("challenge")

    with open("challenge/code/root.rpx", "rb") as f:
        data = f.read()
    
    # The RPX file format is somewhat similar to ELF
    e_shoff = struct.unpack_from(">I", data, 0x20)[0]
    e_shentsize = struct.unpack_from(">H", data, 0x2E)[0]
    e_shnum = struct.unpack_from(">H", data, 0x30)[0]

    # We find the flag verification matrix in the executable by iterating over
    # sections and looking for the Rijndael S-box. The CTF player will probably
    # extract the data from their disassembler instead.
    for i in range(e_shnum):
        offset = e_shoff + e_shentsize * i

        sh_offset = struct.unpack_from(">I", data, offset + 0x10)[0]
        sh_size = struct.unpack_from(">I", data, offset + 0x14)[0]

        section = data[sh_offset : sh_offset + sh_size]

        # Not all sections are compressed, we simply skip the non-compressed
        # sections with a try-except block.
        try:
            decompressed = zlib.decompress(section[4:])
        except zlib.error:
            continue

        # Check if we find the Rijndael S-box
        offset = decompressed.find(b"\x63\x7c\x77\x7b")
        if offset == -1:
            continue

        blob = decompressed[offset : offset + 0xC60]
        break
    else:
        print("Couldn't find rijndael s-box in sections")
        return
    
    # Hardcoded AES-CTR key and nonce
    key = bytes.fromhex("7ddd591ddcf97e8fa78ceccd561fd75a")
    nonce = bytes.fromhex("721ae819081c2ce9a77c4ccc")

    aes = AES.new(key, AES.MODE_CTR, nonce=nonce)
    matrix_data = aes.decrypt(blob[0x400 : 0xC00])

    matrix = []
    for i in range(128):
        row = int.from_bytes(matrix_data[i * 16 : i * 16 + 16], "big")
        matrix.append(row)
    
    target = int.from_bytes(blob[0xC00 : 0xC10], "big")
    input = solve_matrix(matrix, target)

    key = input.to_bytes(16, "big")
    aes = AES.new(key, AES.MODE_ECB)
    flag = aes.encrypt(blob[0xC30:]).rstrip(b"\0")
    print(flag.decode())


if __name__ == "__main__":
    main()
