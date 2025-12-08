
import re
import struct


TYPE_LABEL = 0
TYPE_PARAM = 1
TYPE_CONST = 2
TYPE_INDIRECT = 3
TYPE_REGISTER_INDIRECT = 4
TYPE_REGISTER = 5


class Operand:
	def __init__(self, type, value):
		self.type = type
		self.value = value


class Assembler:
	def __init__(self):
		self.labels = {}
		self.label_refs = {}
		self.address = 0
		self.constants = {}
		self.data = b""
		
		self.jump_instructions = [
			"jmp", "jeq", "jle_u", "jlt_u", "jgt_u",
			"jge_u", "jne", "jlt", "jle", "jgt", "jge"
		]
		
		self.shift_instructions = {
			"shl": 19,
			"shr": 21
		}
		
		self.simple_instructions = {
			"clrfing": 4,
			"ret": 32
		}
		
		self.unary_instructions = {
			"enhance": 5
		}
		
		self.binary_instructions = {
			"finger": 3,
			"mov": 9,
			"cmp": 10,
			"add": 13,
			"sub": 14,
			"xor": 16,
			"and": 17,
			"or": 18,
			"mul": 26
		}
		
		self.registers = [
			"", "rHeap", "rParam", "rText", "rEntity", "rCode"
		]
	
	def write(self, data):
		self.data += data
		self.address += len(data)
	
	def align(self):
		if len(self.data) % 4:
			self.write(bytes(4 - len(self.data) % 4))
	
	def u32(self, value):
		self.write(struct.pack("<I", value))
	
	def assemble(self, text):
		lines = [line.split("#")[0].strip() for line in text.splitlines()]
		for line in lines:
			if line.endswith(":"):
				self.labels[line[:-1]] = None
		
		self.address = 0
		for line in lines:
			if line:
				self.parse(line)
		
		for pos, label in self.label_refs.items():
			self.data = self.data[:pos] + struct.pack("<I", self.labels[label]) + self.data[pos+4:]
	
	def write_const(self, size, value):
		if size in [1, 2]:
			self.u32(value)
		elif size == 3:
			self.u32(value & 0xFFFFFFFF)
			self.u32(value >> 32)
		elif size == 4:
			self.u32(value & 0xFFFFFFFF)
			self.u32((value >> 32) & 0xFFFFFFFF)
			self.u32((value >> 64) & 0xFFFFFFFF)
			self.u32(value >> 96)
		else:
			raise ValueError("Unsupported constant size: %i" %size)
	
	def parse(self, line):
		if line == "mov v0, rParam":
			self.u32(0x02008209)
		elif line == "mov rCall, v0":
			self.u32(0x00060a09)
		elif line == "mode 1":
			self.u32(0x01008008)
		
		elif line.startswith(".base"):
			self.address = eval(line.split(maxsplit=1)[1])
		elif line.startswith(".define"):
			_, name, value = line.split(maxsplit=2)
			self.constants[name] = eval(value)
		elif line.startswith(".space"):
			amount = eval(line.split()[1])
			self.write(bytes(amount))
		elif line.startswith(".string"):
			string = eval(line.split(maxsplit=1)[1])
			self.write(bytes([ord(c) for c in string]) + b"\0")
			self.align()
		elif line.startswith(".hex"):
			string = eval(line.split(maxsplit=1)[1])
			self.write(bytes.fromhex(string))
			self.align()
		elif line.startswith(".u32"):
			self.u32(eval(line.split(maxsplit=1)[1]))
		elif line.endswith(":"):
			self.labels[line[:-1]] = self.address
		else:
			if " " in line:
				mnem, args = line.split(maxsplit=1)
			else:
				mnem = line
				args = ""
			self.parse_instr(mnem, [arg.strip() for arg in args.split(",")])
	
	def parse_instr(self, mnem, args):
		if mnem in self.simple_instructions:
			self.u32(self.simple_instructions[mnem])
		elif mnem in self.jump_instructions:
			target = args[0]
			cond = self.jump_instructions.index(mnem)
			self.u32(11 | (2 << 8) | (1 << 15) | (cond << 18))
			self.label_refs[len(self.data)] = target
			self.u32(0)
		elif mnem == "call":
			target = args[0]
			frame = 0
			if len(args) > 1:
				frame = int(args[1])
				assert not frame & 3
			self.u32(31 | (2 << 8) | (1 << 15) | ((frame >> 2) << 16))
			self.label_refs[len(self.data)] = target
			self.u32(0)
		elif mnem == "wait":
			self.u32(2 | (1 << 15) | (int(args[0]) << 24))
		elif mnem in self.unary_instructions or mnem[:-1] in self.unary_instructions:
			if mnem in self.unary_instructions:
				size = 2
			else:
				if mnem[-1] == "b": size = 0
				elif mnem[-1] == "h": size = 1
				elif mnem[-1] == "q": size = 3
				elif mnem[-1] == "x": size = 4
				else:
					raise ValueError("Unknown opcode: %s" %mnem)
				mnem = mnem[:-1]
			dst = self.parse_operand(args[0])
			opcode = self.unary_instructions[mnem]
			if dst.type == TYPE_PARAM:
				self.u32(opcode | (size << 8) | (dst.value << 16))
		elif mnem in self.shift_instructions or mnem[:-1] in self.shift_instructions:
			if mnem in self.shift_instructions:
				size = 2
			else:
				if mnem[-1] == "b": size = 0
				elif mnem[-1] == "h": size = 1
				elif mnem[-1] == "q": size = 3
				elif mnem[-1] == "x": size = 4
				else:
					raise ValueError("Unknown opcode: %s" %mnem)
				mnem = mnem[:-1]
			dst = self.parse_operand(args[0])
			src = self.parse_operand(args[1])
			opcode = self.shift_instructions[mnem]
			if dst.type == TYPE_PARAM and src.type == TYPE_CONST:
				self.u32(opcode | (size << 8) | (1 << 15) | (dst.value << 16) | (src.value << 24))
			else:
				raise ValueError("Unsupported instruction: %s %s" %(mnem, args))
		elif mnem in self.binary_instructions or mnem[:-1] in self.binary_instructions:
			if mnem in self.binary_instructions:
				size = 2
			else:
				if mnem[-1] == "b": size = 0
				elif mnem[-1] == "h": size = 1
				elif mnem[-1] == "q": size = 3
				elif mnem[-1] == "x": size = 4
				else:
					raise ValueError("Unknown opcode: %s" %mnem)
				mnem = mnem[:-1]
			dst = self.parse_operand(args[0])
			src = self.parse_operand(args[1])
			opcode = self.binary_instructions[mnem]
			if dst.type == TYPE_PARAM and src.type == TYPE_CONST:
				if size == 0:
					self.u32(opcode | (size << 8) | (1 << 15) | (dst.value << 16) | (src.value << 24))
				else:
					self.u32(opcode | (size << 8) | (1 << 15) | (dst.value << 16))
					self.write_const(size, src.value)
			elif dst.type == TYPE_PARAM and src.type == TYPE_LABEL and size == 2:
				self.u32(opcode | (size << 8) | (1 << 15) | (dst.value << 16))
				self.label_refs[len(self.data)] = src.value
				self.u32(0)
			elif dst.type == TYPE_PARAM and src.type == TYPE_PARAM:
				self.u32(opcode | (size << 8) | (dst.value << 16) | (src.value << 24))
			elif dst.type == TYPE_PARAM and src.type == TYPE_INDIRECT:
				self.u32(opcode | (size << 8) | (7 << 12) | (dst.value << 16) | (src.value << 24))
			elif dst.type == TYPE_INDIRECT and src.type == TYPE_PARAM:
				self.u32(opcode | (size << 8) | (1 << 11) | (7 << 12) | (dst.value << 16) | (src.value << 24))
			elif dst.type == TYPE_INDIRECT and src.type == TYPE_CONST:
				if size == 0:
					self.u32(opcode | (size << 8) | (1 << 11) | (7 << 12) | (1 << 15) | (dst.value << 16) | (src.value << 24))
				else:
					self.u32(opcode | (size << 8) | (1 << 11) | (7 << 12) | (1 << 15) | (dst.value << 16))
					self.write_const(size, src.value)
			elif dst.type == TYPE_REGISTER_INDIRECT and src.type == TYPE_PARAM:
				reg = self.registers.index(dst.value[0])
				self.u32(opcode | (size << 8) | (1 << 11) | (reg << 12) | (dst.value[1] << 16) | (src.value << 24))
			elif dst.type == TYPE_REGISTER and src.type == TYPE_CONST:
				self.u32(opcode | (size << 8) | (1 << 11) | (1 << 15) | (dst.value << 16))
				self.write_const(size, src.value)
			else:
				raise ValueError("Unsupported instruction: %s %s (%i)" %(mnem, args, size))
		else:
			raise ValueError("Unknown opcode: %s" %mnem)
	
	def parse_operand(self, operand):
		if operand in self.labels:
			return Operand(TYPE_LABEL, operand)
		elif operand in self.constants:
			return Operand(TYPE_CONST, self.constants[operand])
		elif re.match("v[0-9]+", operand):
			index = int(operand[1:])
			return Operand(TYPE_PARAM, index)
		elif operand.isdecimal():
			return Operand(TYPE_CONST, int(operand))
		elif operand.startswith("0x"):
			return Operand(TYPE_CONST, eval(operand))
		elif re.match(r"\[v[0-9]+\]", operand):
			param = int(operand[2:-1])
			return Operand(TYPE_INDIRECT, param)
		elif re.match(r"\[[a-zA-Z]+\+v[0-9]+\]", operand):
			reg = operand.split("+")[0][1:]
			param = int(operand.split("+v")[1][:-1])
			return Operand(TYPE_REGISTER_INDIRECT, (reg, param))
		elif operand in self.registers:
			return Operand(TYPE_REGISTER, self.registers.index(operand))
		else:
			raise ValueError("Failed to parse operand: %s" %operand)
