
import struct

class StreamOut:
	def __init__(self, endian):
		self.endian = endian
		self.data = bytearray()
		self.pos = 0
		self.stack = []
		
	def push(self): self.stack.append(self.pos)
	def pop(self): self.pos = self.stack.pop()
		
	def get(self): return bytes(self.data)
	def size(self): return len(self.data)
	def tell(self): return self.pos
	def seek(self, pos):
		if pos > len(self.data):
			self.data += bytes(pos - len(self.data))
		self.pos = pos
	def skip(self, num): self.seek(self.pos + num)
	def align(self, num): self.skip((num - self.pos % num) % num)
	def available(self): return len(self.data) - self.pos
	def eof(self): return self.pos >= len(self.data)
		
	def write(self, data):
		self.data[self.pos : self.pos + len(data)] = data
		self.pos += len(data)
		
	def pad(self, num, char=b"\0"):
		self.write(char * num)
		
	def ascii(self, data):
		self.write(data.encode("ascii"))
		
	def u8(self, value): self.write(bytes([value]))
	def u16(self, value): self.write(struct.pack(self.endian + "H", value))
	def u32(self, value): self.write(struct.pack(self.endian + "I", value))
	def u64(self, value): self.write(struct.pack(self.endian + "Q", value))
	
	def s8(self, value): self.write(struct.pack("b", value))
	def s16(self, value): self.write(struct.pack(self.endian + "h", value))
	def s32(self, value): self.write(struct.pack(self.endian + "i", value))
	def s64(self, value): self.write(struct.pack(self.endian + "q", value))
	
	def u24(self, value):
		if self.endian == ">":
			self.u16(value >> 8)
			self.u8(value & 0xFF)
		else:
			self.u8(value & 0xFF)
			self.u16(value >> 8)
			
	def float(self, value): self.write(struct.pack(self.endian + "f", value))
	def double(self, value): self.write(struct.pack(self.endian + "d", value))
	
	def bool(self, value): self.u8(1 if value else 0)
	def char(self, value): self.u8(ord(value))
	def wchar(self, value): self.u16(ord(value))
	
	def chars(self, data): self.repeat(data, self.char)
	def wchars(self, data): self.repeat(data, self.wchar)
	
	def repeat(self, list, func):
		for value in list:
			func(value)
