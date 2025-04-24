
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
import struct
import sys
import time


R_HEAP = 1
R_PARAM = 2
R_TEXT = 3
R_CODE = 5
R_CALL = 6
R_STATUS = 7
R_BODY = 9
R_SPLINE = 10
R_PC = 15


MASK = 0xFFFFFFFF


class CPUError(Exception):
	pass


class Signal:
	def __init__(self):
		self.listeners = []
	
	def connect(self, listener):
		self.listeners.append(listener)
	
	def emit(self, *args, **kwargs):
		for listener in self.listeners:
			listener(*args, **kwargs)


class Memory:
	def __init__(self, size):
		self.data = bytearray(size)
	
	def size(self):
		return len(self.data)
	
	def read(self, addr, size):
		return self.data[addr:addr+size]
	
	def write(self, addr, data):
		self.data[addr:addr+len(data)] = data
	
	def u8(self, addr): return self.data[addr]
	def u16(self, addr): return struct.unpack_from("<H", self.data, addr)[0]
	def u32(self, addr): return struct.unpack_from("<I", self.data, addr)[0]
	def u64(self, addr): return struct.unpack_from("<Q", self.data, addr)[0]
	
	def write_u8(self, addr, value): struct.pack_into("<B", self.data, addr, value)
	def write_u16(self, addr, value): struct.pack_into("<H", self.data, addr, value)
	def write_u32(self, addr, value): struct.pack_into("<I", self.data, addr, value)
	def write_u64(self, addr, value): struct.pack_into("<Q", self.data, addr, value)


class Finger:
	def __init__(self):
		self.reset()
	
	def reset(self):
		self.v0 = 0
		self.v1 = 0
		self.v2 = 0
		self.v3 = 0
		self.count = 0
	
	def update(self, value):
		self.count += 1
		
		v0 = value & MASK
		v1 = (value >> 32) & MASK
		v2 = (value >> 64) & MASK
		v3 = value >> 96
		
		r = v0
		v0 = (v0 >> 7) | (v1 << 25) & MASK
		v1 = (v1 >> 7) | (v2 << 25) & MASK
		v2 = (v2 >> 7) | (v3 << 25) & MASK
		v3 = (v3 >> 7) | (r << 25) & MASK
		
		self.v0 = ((self.v0 & 0x6487ED51) + self.v2 + (v0 ^ 0x10B4611A)) & MASK
		self.v1 = ((self.v1 ^ 0x62633145) + self.v3 + (v1 ^ 0xC06E0E68)) & MASK
		self.v2 = ((self.v2 ^ 0x94812704) + self.v0 + (v2 ^ 0x4533E63A)) & MASK
		self.v3 = ((self.v3 & 0x0105DF53) + self.v1 + (v3 ^ 0x1D89CD91)) & MASK
		
		v0 = (self.v1 + self.v3) & MASK
		v1 = (self.v2 + self.v0) & MASK
		v2 = (self.v3 + self.v2) & MASK
		v3 = (self.v0 + self.v1) & MASK
		
		r = v0
		v0 = (v0 >> 15) | (v1 << 17) & MASK
		v1 = (v1 >> 15) | (v2 << 17) & MASK
		v2 = (v2 >> 15) | (v3 << 17) & MASK
		v3 = (v3 >> 15) | (r << 17) & MASK
		
		self.v0 = ((self.v0 & 0x28A5043C) + self.v2 + (v0 ^ 0xC71A026E)) & MASK
		self.v1 = ((self.v1 ^ 0xF7CA8CD9) + self.v3 + (v1 ^ 0xE69D218D)) & MASK
		self.v2 = ((self.v2 ^ 0x98158536) + self.v0 + (v2 ^ 0xF92F8A1B)) & MASK
		self.v3 = ((self.v3 & 0xA7F09AB6) + self.v1 + (v3 ^ 0xB6A8E122)) & MASK
		
		v0 = (self.v1 + self.v3) & MASK
		v1 = (self.v2 + self.v0) & MASK
		v2 = (self.v3 + self.v2) & MASK
		v3 = (self.v0 + self.v1) & MASK
		
		r = v0
		v0 = (v0 >> 21) | (v1 << 11) & MASK
		v1 = (v1 >> 21) | (v2 << 11) & MASK
		v2 = (v2 >> 21) | (v3 << 11) & MASK
		v3 = (v3 >> 21) | (r << 11) & MASK
		
		self.v0 = ((self.v0 & 0xF242DABB) + self.v2 + (v0 ^ 0x312F3F63)) & MASK
		self.v1 = ((self.v1 ^ 0x7A262174) + self.v3 + (v1 ^ 0xD31BF6B5)) & MASK
		self.v2 = ((self.v2 ^ 0x85FFAE5B) + self.v0 + (v2 ^ 0x7A035BF6)) & MASK
		self.v3 = ((self.v3 & 0xF71C35FD) + self.v1 + (v3 ^ 0xAD44CFD2)) & MASK
		
		v0 = (self.v1 + self.v3) & MASK
		v1 = (self.v2 + self.v0) & MASK
		v2 = (self.v3 + self.v2) & MASK
		v3 = (self.v0 + self.v1) & MASK
		
		return v0 | (v1 << 32) | (v2 << 64) | (v3 << 96)
	
	def enhance(self):
		finger = Finger()
		finger.v0 = self.v0
		finger.v1 = self.v1
		finger.v2 = self.v2
		finger.v3 = self.v3
		value = self.count
		for i in range(64):
			value = finger.update(value)
		return finger.v0 | (finger.v1 << 32) | (finger.v2 << 64) | (finger.v3 << 96)


class CPU:
	def __init__(self, memory, code, param):
		self.memory = memory
		self.breakpoints = [] # Add addresses here to enable breakpoints
		
		self.regs = [0] * 16
		self.regs[R_PARAM] = param
		self.regs[R_CODE] = code
		self.regs[R_BODY] = self.memory.size()
		self.regs[R_PC] = code
		
		self.stack = 0
		self.delta = 0
		
		self.finger = Finger()
		
		self.opcodes = {
			2: self.opcodeWait,
			3: self.opcodeFinger,
			4: self.opcodeClearFinger,
			5: self.opcodeEnhance,
			8: self.opcodeMode,
			9: self.opcodeMov,
			10: self.opcodeCmp,
			11: self.opcodeJump,
			13: self.opcodeAdd,
			14: self.opcodeSub,
			15: self.opcodeNot,
			16: self.opcodeXor,
			17: self.opcodeAnd,
			18: self.opcodeOr,
			19: self.opcodeShl,
			20: self.opcodeAsr,
			21: self.opcodeShr,
			26: self.opcodeMul,
			27: self.opcodeDiv,
			31: self.opcodeCall,
			32: self.opcodeRet,
			41: self.opcodeTime,
			42: self.opcodeDtime
		}
	
	def fetch(self):
		value = self.memory.u32(self.regs[R_PC])
		self.regs[R_PC] += 4
		return value
	
	def run(self, cycles=None):
		self.delay = 0
		while cycles is None or cycles > 0:
			addr = self.regs[R_PC]
			try:
				self.step()
			except Exception as e:
				self.regs[R_PC] = addr
				raise
			
			if self.regs[R_PC] in self.breakpoints:
				self.delay = 0
				return True
			
			if self.delay:
				self.delay = 0
				return False
			
			if cycles is not None:
				cycles -= 1
		return False
	
	def step(self):
		instr = self.fetch()
		opcode = instr & 0xFF
		if opcode in self.opcodes:
			self.opcodes[opcode](instr)
		else:
			raise CPUError("unknown opcode: %i" %opcode)
	
	def loadMemory(self, instr, addr):
		type = (instr >> 8) & 7
		if type == 0: return self.memory.u8(addr)
		elif type == 1: return self.memory.u16(addr)
		elif type == 2: return self.memory.u32(addr)
		elif type == 3: return self.memory.u64(addr)
		elif type == 4:
			return self.memory.u64(addr) | (self.memory.u64(addr + 8) << 64)
		else:
			raise CPUError("unsupported load type: %i" %type)
	
	def storeMemory(self, instr, addr, value):
		type = (instr >> 8) & 7
		if type == 0: self.memory.write_u8(addr, value & 0xFF)
		elif type == 1: self.memory.write_u16(addr, value & 0xFFFF)
		elif type == 2: self.memory.write_u32(addr, value & 0xFFFFFFFF)
		elif type == 3: self.memory.write_u64(addr, value & ((1 << 64) - 1))
		elif type == 4:
			value &= (1 << 128) - 1
			self.memory.write_u64(addr, value & ((1 << 64) - 1))
			self.memory.write_u64(addr + 8, value >> 64)
		else:
			raise CPUError("unsupported store type: %i" %type)
	
	def getSrc(self, instr):
		if instr & 0x8000:
			type = (instr >> 8) & 7
			if type == 0: return instr >> 24
			elif type == 1: return self.fetch() & 0xFFFF
			elif type == 2:
				register = instr >> 24
				if register == 0: return self.fetch()
				else:
					return self.regs[register]
			elif type == 3: return self.fetch() | (self.fetch() << 32)
			elif type == 4:
				return self.fetch() | (self.fetch() << 32) | (self.fetch() << 64) | (self.fetch() << 96)
			else:
				raise CPUError("floating point src not supported")
		
		offset = instr >> 24
		addr = self.regs[R_PARAM] + offset
		
		if instr & 0x800:
			return self.loadMemory(instr, addr)
		
		register = (instr >> 12) & 7
		if register == 0: return self.loadMemory(instr, addr)
		elif register == 7:
			addr = self.memory.u32(addr)
			return self.loadMemory(instr, addr)
		else:
			addr = self.regs[register] + self.memory.u32(addr)
			return self.loadMemory(instr, addr)
	
	def getSrcAlt(self, instr):
		if instr & 0x8000:
			if instr & 0x700 == 0x500:
				return self.getSrc(instr - 0x300)
			return instr >> 24
		return self.getSrc(instr)
	
	def getDst(self, instr):
		slot = (instr >> 16) & 0xFF
		if instr & 0x800:
			register = (instr >> 12) & 7
			if register == 0: return self.regs[slot]
			elif register == 7:
				addr = self.regs[R_PARAM] + slot
				addr = self.memory.u32(addr)
				return self.loadMemory(instr, addr)
			else:
				addr = self.regs[register] + self.memory.u32(self.regs[R_PARAM] + slot)
				return self.loadMemory(instr, addr)
		
		addr = self.regs[R_PARAM] + slot
		return self.loadMemory(instr, addr)
	
	def getSignedDst(self, instr):
		type = (instr >> 8) & 7
		value = self.getDst(instr)
		if type == 0:
			if value & 0x80: value -= 0x100
		elif type == 2:
			if value & 0x80000000: value -= 0x100000000
		else:
			raise CPUError("unsupported signed dst type: %i" %type)
		return value
	
	def setDst(self, instr, value):
		slot = (instr >> 16) & 0xFF
		if instr & 0x800:
			register = (instr >> 12) & 7
			if register == 0: self.regs[slot] = value
			elif register == 7:
				addr = self.regs[R_PARAM] + slot
				addr = self.memory.u32(addr)
				self.storeMemory(instr, addr, value)
			else:
				addr = self.regs[register] + self.memory.u32(self.regs[R_PARAM] + slot)
				self.storeMemory(instr, addr, value)
		else:
			addr = self.regs[R_PARAM] + slot
			self.storeMemory(instr, addr, value)
	
	def checkCondition(self, cond):
		if cond == 0: return True
		elif cond == 1: return self.regs[R_STATUS] & 2
		elif cond == 2: return self.regs[R_STATUS] >> 31
		elif cond == 3: return self.regs[R_STATUS] & 0x80000002
		elif cond == 4: return not self.regs[R_STATUS] & 0x80000002
		elif cond == 5: return not self.regs[R_STATUS] >> 31
		elif cond == 6: return not self.regs[R_STATUS] & 2
		elif cond == 7: return self.regs[R_STATUS] & 1
		elif cond == 8: return self.regs[R_STATUS] & 3
		elif cond == 9: return not self.regs[R_STATUS] & 3
		elif cond == 10: return not self.regs[R_STATUS] & 1
		else:
			raise CPUError("unsupported condition code: %i" %cond)
	
	def opcodeWait(self, instr):
		self.delay = self.getSrc(instr)
	
	def opcodeFinger(self, instr):
		self.setDst(instr, self.finger.update(self.getSrc(instr)))
	
	def opcodeClearFinger(self, instr):
		self.finger.reset()
	
	def opcodeEnhance(self, instr):
		value = self.finger.enhance()
		self.setDst(instr, value)
	
	def opcodeMode(self, instr):
		value = self.getSrc(instr)
		self.regs[R_STATUS] = (self.regs[R_STATUS] & ~4) | ((value & 1) << 2)
	
	def opcodeMov(self, instr):
		value = self.getSrc(instr)
		self.setDst(instr, value)
	
	def opcodeCmp(self, instr):
		type = (instr >> 8) & 7
		src = self.getSrc(instr)
		dst = self.getDst(instr)
		if type == 0:
			value = (dst - src) & 0xFF
			if value == 0: cmp = 2
			else:
				cmp = (value >> 7) << 31
				cmp |= (src ^ dst ^ value) >> 7
		elif type == 1:
			value = (dst - src) & 0xFFFF
			if value == 0: cmp = 2
			else:
				cmp = (value >> 15) << 31
				cmp |= (src ^ dst ^ value) >> 15
		elif type == 2:
			value = (dst - src) & 0xFFFFFFFF
			if value == 0: cmp = 2
			else:
				cmp = value & 0x80000000
				cmp |= (src ^ dst ^ value) >> 31
		else:
			raise CPUError("unsupported comparison type: %i" %type)
		self.regs[R_STATUS] = (self.regs[R_STATUS] & ~0x80000003) | cmp
	
	def opcodeJump(self, instr):
		addr = self.getSrc(instr)
		cond = (instr >> 18) & 0x3F
		if self.checkCondition(cond):
			self.regs[R_PC] = self.regs[R_CODE] + addr
	
	def opcodeAdd(self, instr):
		value1 = self.getDst(instr)
		value2 = self.getSrc(instr)
		self.setDst(instr, value1 + value2)
	
	def opcodeSub(self, instr):
		value1 = self.getDst(instr)
		value2 = self.getSrc(instr)
		self.setDst(instr, value1 - value2)
	
	def opcodeNot(self, instr):
		value = self.getSrc(instr)
		self.setDst(instr, ~value)
	
	def opcodeXor(self, instr):
		value1 = self.getDst(instr)
		value2 = self.getSrc(instr)
		self.setDst(instr, value1 ^ value2)
	
	def opcodeAnd(self, instr):
		value1 = self.getDst(instr)
		value2 = self.getSrc(instr)
		self.setDst(instr, value1 & value2)
	
	def opcodeOr(self, instr):
		value1 = self.getDst(instr)
		value2 = self.getSrc(instr)
		self.setDst(instr, value1 | value2)
	
	def opcodeShl(self, instr):
		value1 = self.getDst(instr)
		value2 = self.getSrcAlt(instr)
		self.setDst(instr, value1 << value2)
	
	def opcodeAsr(self, instr):
		value1 = self.getSignedDst(instr)
		value2 = self.getSrcAlt(instr)
		self.setDst(instr, value1 >> value2)
	
	def opcodeShr(self, instr):
		value1 = self.getDst(instr)
		value2 = self.getSrcAlt(instr)
		self.setDst(instr, value1 >> value2)
	
	def opcodeMul(self, instr):
		value1 = self.getDst(instr)
		value2 = self.getSrc(instr)
		self.setDst(instr, value1 * value2)
	
	def opcodeDiv(self, instr):
		value1 = self.getSignedDst(instr)
		value2 = self.getSrc(instr)
		self.setDst(instr, value1 // value2)
	
	def opcodeCall(self, instr):
		addr = self.getSrc(instr)
		frame = (instr >> 14) & 0x3FC
		
		self.memory.write_u32(self.regs[R_CALL] + self.stack + 4, self.regs[R_PARAM])
		self.memory.write_u32(self.regs[R_CALL] + self.stack + 8, self.regs[R_PC])
		self.stack += 8
		
		self.regs[R_PARAM] += frame
		self.regs[R_PC] = self.regs[R_CODE] + addr
	
	def opcodeTime(self, instr):
		self.setDst(instr, time.monotonic() * 1000)
	
	def opcodeDtime(self, instr):
		current = time.monotonic() * 1000
		diff = int(current - self.delta)
		self.delta = current
		self.setDst(instr, diff)
	
	def opcodeRet(self, instr):
		self.stack -= 8
		self.regs[R_PARAM] = self.memory.u32(self.regs[R_CALL] + self.stack + 4)
		self.regs[R_PC] = self.memory.u32(self.regs[R_CALL] + self.stack + 8)


class InputDevice:
	def __init__(self, memory, base):
		self.memory = memory
		self.base = base


class TextDisplay:
	DISPLAY_CONFIG = 0
	CURSOR_POS = 1
	CELL_COUNT = 2
	CELL_OFFSET = 3
	DISPLAY_BUFFER = 4
	
	FLAG_CURSOR_ENABLED = 1 << 27
	FLAG_SCANLINE_FILTER = 1 << 28
	FLAG_SINGLE_REDRAW = 1 << 29
	FLAG_PERMANENT_REDRAW = 1 << 30
	FLAG_RESET_SIZE = 1 << 31
	
	def __init__(self, memory, base):
		self.memory = memory
		self.base = base
		
		self.set(self.DISPLAY_CONFIG, (1 << 12) | (13 << 8) | (7 << 4) | 2 | self.FLAG_CURSOR_ENABLED)
		self.set(self.CURSOR_POS, 0)
		self.set(self.CELL_COUNT, (25 << 16) | 80)
		self.set(self.CELL_OFFSET, 4)
		
	def get(self, reg): return self.memory.u32(self.base + reg * 4)
	def set(self, reg, value): self.memory.write_u32(self.base + reg * 4, value)
	
	def update(self):
		config = self.get(self.DISPLAY_CONFIG)
		if not config & self.FLAG_RESET_SIZE:
			config |= self.FLAG_RESET_SIZE
			self.set(self.DISPLAY_CONFIG, config)
			self.set(self.CELL_COUNT, (25 << 16) | 80)


class Emulator:
	def __init__(self, program):
		self.memory = Memory(0x40000)
		self.memory.write(0x4400, program)
		
		self.input = InputDevice(self.memory, 0)
		self.display = TextDisplay(self.memory, 0x40)
		self.cpu = CPU(self.memory, 0x4400, 0x4400 + len(program))
		
		self.finished = Signal()
		self.error = Signal()
		self.breakpoint = Signal()
	
	def run(self, cycles=None):
		try:
			if self.cpu.run(cycles):
				self.breakpoint.emit()
			self.display.update()
		except Exception as e:
			self.error.emit(str(e))
		self.finished.emit()
			


class Disassembler:
	def __init__(self):
		self.pc = 0
		self.data = b""
		self.lines = []
		self.addresses = []
		
		self.opcodes = {
			0: self.opcodeSimple("halt"),
			2: self.opcodeUnary("wait"),
			3: self.opcodeUnary("finger"),
			4: self.opcodeSimple("clrfing"),
			8: self.opcodeUnary("mode"),
			9: self.opcodeBinary("mov"),
			10: self.opcodeBinary("cmp"),
			11: self.opcodeJump,
			13: self.opcodeBinary("add"),
			14: self.opcodeBinary("sub"),
			15: self.opcodeUnary("not"),
			16: self.opcodeBinary("xor"),
			17: self.opcodeBinary("and"),
			18: self.opcodeBinary("or"),
			19: self.opcodeBinaryAlt("shl"),
			20: self.opcodeBinaryAlt("asr"),
			21: self.opcodeBinaryAlt("shr"),
			22: self.opcodeBinaryAlt("rol"),
			23: self.opcodeBinaryAlt("ror"),
			25: self.opcodeBinary("neg"),
			26: self.opcodeBinary("mul"),
			27: self.opcodeBinary("div"),
			28: self.opcodeBinary("mod"),
			29: self.opcodeBinary("divu"),
			30: self.opcodeBinary("modu"),
			31: self.opcodeCall,
			32: self.opcodeSimple("ret"),
			41: self.opcodeDst("time"),
			42: self.opcodeDst("dtime")
		}
		
		self.registers = [
			"?", "rHeap", "rParam", "rText", "rEntity", "rCode", "rCall",
			"status", "?", "body", "spine", "free", "seed", "rSig",
			"rVirt", "PC"
		]
		
		self.suffixes = ["b", "h", "", "q", "x", "f", "d", "t"]
		
		self.conditions = ["mp", "eq", "le_u", "lt_u", "ge_u", "gt_u", "ne", "le", "lt", "ge", "gt"]
	
	def fetch(self):
		value = struct.unpack_from("<I", self.data, self.pc)[0]
		self.pc += 4
		return value
	
	def disassemble(self, data):
		self.data = data
		self.pc = 0
		
		self.lines = []
		self.addresses = []
		while self.pc < len(data):
			addr = self.pc
			instr = self.fetch()
			text = self.disassembleInstr(instr, addr)
			
			line = "%04X:  %08X  %s" %(addr, instr, text)
			self.lines.append(line)
			self.addresses.append(addr)
			
	def disassembleInstr(self, instr, addr):
		opcode = instr & 0xFF
		if opcode in self.opcodes:
			return self.opcodes[opcode](instr, addr)
		return "???"
	
	def getSuffix(self, instr):
		return self.suffixes[(instr >> 8) & 7]
	
	def getSrc(self, instr):
		if instr & 0x8000: # Immediate
			size = (instr >> 8) & 7
			if size == 0: return "0x%X" %(instr >> 24)
			elif size == 1:
				return "0x%X" %(self.fetch() & 0xFFFF)
			elif size == 2:
				register = instr >> 24
				if register == 0: return "0x%X" %self.fetch()
				elif register < len(self.registers):
					return self.registers[register]
				return "?"
			elif size == 3:
				a = self.fetch()
				b = self.fetch()
				return "0x%X%08X" %(b, a)
			elif size in [4, 7]:
				a, b, c, d = self.fetch(), self.fetch(), self.fetch(), self.fetch()
				return "0x%X%08X%08X%08X" %(d, c, b, a)
			elif size == 5:
				return "%ff" %struct.unpack("f", struct.pack("I", self.fetch()))[0]
			elif size == 6:
				return "%f" %struct.unpack("d", struct.pack("Q", self.fetch() | (self.fetch() << 32)))[0]
		
		offset = instr >> 24
		param = "v%i" %offset
		if instr & 0x800:
			return param
		
		register = (instr >> 12) & 7
		if register == 0: return param
		elif register == 7: return "[%s]" %param
		else:
			return "[%s+%s]" %(self.registers[register], param)
	
	def getSrcAlt(self, instr):
		if instr & 0x8000:
			if instr & 0x700 == 0x500:
				return self.getSrc(instr - 0x300)
			return str(instr >> 24)
		return self.getSrc(instr)
	
	def getDst(self, instr):
		slot = (instr >> 16) & 0xFF
		param = "v%i" %slot
		if instr & 0x800:
			basereg = (instr >> 12) & 7
			if basereg == 0:
				if slot < len(self.registers):
					return self.registers[slot]
				return "???"
			elif basereg == 7:
				return "[%s]" %param
			else:
				return "[%s+%s]" %(self.registers[basereg], param)
		return param
	
	def opcodeSimple(self, name):
		def disassemble(instr, addr):
			return name
		return disassemble
	
	def opcodeUnary(self, name):
		def disassemble(instr, addr):
			suffix = self.getSuffix(instr)
			src = self.getSrc(instr)
			return "%s%s %s" %(name, suffix, src)
		return disassemble
	
	def opcodeDst(self, name):
		def disassemble(instr, addr):
			suffix = self.getSuffix(instr)
			dst = self.getDst(instr)
			return "%s%s %s" %(name, suffix, dst)
		return disassemble
	
	def opcodeBinary(self, name):
		def disassemble(instr, addr):
			suffix = self.getSuffix(instr)
			src = self.getSrc(instr)
			dst = self.getDst(instr)
			return "%s%s %s, %s" %(name, suffix, dst, src)
		return disassemble
	
	def opcodeBinaryAlt(self, name):
		def disassemble(instr, addr):
			suffix = self.getSuffix(instr)
			src = self.getSrcAlt(instr)
			dst = self.getDst(instr)
			return "%s%s %s, %s" %(name, suffix, dst, src)
		return disassemble
	
	def opcodeJump(self, instr, addr):
		src = self.getSrc(instr)
		cond = (instr >> 18) & 0x3F
		if cond < len(self.conditions):
			cond = self.conditions[cond]
		else:
			cond = "??"
		return "j%s %s" %(cond, src)
	
	def opcodeCall(self, instr, addr):
		src = self.getSrc(instr)
		frame = (instr >> 14) & 0x3FC
		if frame:
			return "call %s [%i]" %(src, frame)
		else:
			return "call %s" %src
	
	def getLine(self, addr):
		if addr in self.addresses:
			return self.addresses.index(addr)
		
		for i in range(len(self.addresses) - 1):
			if self.addresses[i] < addr < self.addresses[i+1]:
				return i
	
	def text(self):
		return "\n".join(self.lines)


class DisassemblyWidget(QPlainTextEdit):
	def __init__(self, emulator):
		super().__init__()
		self.emulator = emulator
		self.memory = emulator.memory
		
		self.disassembler = Disassembler()
		
		self.setWordWrapMode(QTextOption.WrapMode.NoWrap)
		self.setTextInteractionFlags(Qt.TextInteractionFlag.NoTextInteraction)
		self.setFont(QFont("monospace"))
		
		self.error = False
		
		self.updateText()
		
		self.showAddress(self.emulator.cpu.regs[R_PC])
		
		self.emulator.error.connect(self.handleError)
		self.emulator.finished.connect(self.updateCPU)
	
	def getAddrColors(self):
		items = []
		if self.error:
			items.append((self.emulator.cpu.regs[R_PC], (255, 0, 0)))
		else:
			items.append((self.emulator.cpu.regs[R_PC], (0, 255, 0)))
		return items
	
	def getLineColors(self):
		items = self.getAddrColors()
		
		lines = {}
		for addr, color in items:
			line = self.disassembler.getLine(addr)
			if line not in lines:
				lines[line] = []
			lines[line].append(color)
		
		selections = {}
		for line, colors in lines.items():
			color = [sum(elem) // len(colors) for elem in zip(*colors)]
			selections[line] = color
		return selections
	
	def updateText(self):
		data = self.memory.read(0, self.memory.size())
		self.disassembler.disassemble(data)
		self.setPlainText(self.disassembler.text())
		
		selections = []
		colors = self.getLineColors()
		for line, color in colors.items():
			cursor = self.textCursor()
			cursor.movePosition(QTextCursor.MoveOperation.Down, n=line)
			cursor.select(QTextCursor.SelectionType.LineUnderCursor)
			format = QTextCharFormat()
			format.setBackground(QBrush(QColor(*color)))
			selection = QTextEdit.ExtraSelection()
			selection.cursor = cursor
			selection.format = format
			selections.append(selection)
		
		self.setExtraSelections(selections)
	
	def handleError(self, e):
		self.error = True
	
	def updateCPU(self):
		self.updateText()
		self.showAddress(self.emulator.cpu.regs[R_PC])
	
	def showAddress(self, addr):
		line = self.disassembler.getLine(addr)
		block = self.document().findBlockByLineNumber(line)
		cursor = QTextCursor(block)
		self.setTextCursor(cursor)
		self.centerCursor()


class RegisterWidget(QPlainTextEdit):
	def __init__(self, emulator):
		super().__init__()
		self.emulator = emulator
		self.emulator.finished.connect(self.updateRegs)
		
		self.setWordWrapMode(QTextOption.WrapMode.NoWrap)
		self.setTextInteractionFlags(Qt.TextInteractionFlag.NoTextInteraction)
		self.setFont(QFont("monospace"))
		
		self.updateRegs()
	
	def updateRegs(self):
		lines = []
		lines.append("rHeap: 0x%X" %self.emulator.cpu.regs[R_HEAP])
		lines.append("rParam: 0x%X" %self.emulator.cpu.regs[R_PARAM])
		lines.append("rText: 0x%X" %self.emulator.cpu.regs[R_TEXT])
		lines.append("")
		lines.append("Param:")
		for i in range(10):
			lines.append("  %08X" %self.emulator.memory.u32(self.emulator.cpu.regs[R_PARAM] + i * 4))
		lines.append("")
		lines.append("fingercnt: %i" %self.emulator.cpu.finger.count)
		self.setPlainText("\n".join(lines))


class DisplayWidget(QWidget):
	def __init__(self, emulator):
		super().__init__()
		self.emulator = emulator
		self.memory = emulator.memory
		self.display = emulator.display
		
		self.colors = [
			"#000", "#00a", "#0a0", "#0aa", "#a00", "#a0a", "#a50", "#aaa",
			"#555", "#55f", "#5f5", "#5ff", "#f55", "#f5f", "#ff5", "#fff"
		]
		
		self.pixmap = QPixmap(720, 400)
		
		self.fonts = []
		font = QPixmap("challenge/img/sc-font-9x16.png")
		mask = font.mask()
		for i in range(16):
			colored = QPixmap(font.size())
			colored.fill(QColor(self.colors[i]))
			colored.setMask(mask)
			self.fonts.append(colored)
		
		self.emulator.finished.connect(self.update)
		
		self.setFocusPolicy(Qt.FocusPolicy.ClickFocus)
	
	def keyPressEvent(self, e):
		super().keyPressEvent(e)
		
		config = self.memory.u32(0)
		if e.key() == Qt.Key.Key_Backspace:
			self.memory.write_u32(0, config | 0x10)
			self.memory.write_u32(12, 8)
		elif e.key() == Qt.Key.Key_Return:
			self.memory.write_u32(0, config | 0x10)
			self.memory.write_u32(12, 13)
		else:
			text = e.text()
			if len(text) == 1:
				self.memory.write_u32(0, config | 0x40)
				self.memory.write_u32(16, ord(text))
	
	def backgroundColor(self):
		config = self.display.get(self.display.DISPLAY_CONFIG)
		return QColor(self.colors[(config >> 16) & 0xF])
	
	def redrawPixmap(self):
		painter = QPainter(self.pixmap)
		painter.setPen(Qt.PenStyle.NoPen)
		for y in range(25):
			for x in range(80):
				cell = self.memory.u16(0x50 + (y * 80 + x) * 2)
				char = cell & 0xFF
				sx = 2 + (char % 32) * 12
				sy = 2 + (char // 32) * 19
				painter.setBrush(QColor(self.colors[cell >> 12]))
				painter.drawRect(x * 9, y * 16, 9, 16)
				painter.drawPixmap(x * 9, y * 16, self.fonts[(cell >> 8) & 0xF], sx, sy, 9, 16)
	
	def paintEvent(self, e):
		config = self.display.get(self.display.DISPLAY_CONFIG)
		
		x = (self.width() - self.pixmap.width()) // 2
		y = (self.height() - self.pixmap.height()) // 2
		
		if config & (self.display.FLAG_SINGLE_REDRAW | self.display.FLAG_PERMANENT_REDRAW):
			config &= ~self.display.FLAG_SINGLE_REDRAW
			self.redrawPixmap()
		
		painter = QPainter(self)
		painter.setBrush(self.backgroundColor())
		painter.drawRect(self.rect())
		painter.drawPixmap(x, y, self.pixmap)


class MainWidget(QSplitter):
	def __init__(self, emulator):
		super().__init__()
		self.emulator = emulator
		
		self.disassembly = DisassemblyWidget(self.emulator)
		self.display = DisplayWidget(self.emulator)
		self.registers = RegisterWidget(self.emulator)
		
		self.addWidget(self.disassembly)
		self.addWidget(self.display)
		self.addWidget(self.registers)


class ToolBar(QToolBar):
	def __init__(self):
		super().__init__("Tools")
		self.run = QAction("Run")
		self.step = QAction("Step")
		self.stop = QAction("Stop")
		
		self.addAction(self.run)
		self.addAction(self.step)
		self.addAction(self.stop)
	
	def contextMenuEvent(self, e):
		pass


class MainWindow(QMainWindow):
	def __init__(self, settings):
		super().__init__()
		self.settings = settings
		
		self.initializeEmulator()
		self.initializeGeometry()
		self.initializeWidgets()
		
		self.setWindowTitle("Skullcode")
	
	def initializeEmulator(self):
		with open("build/program.bin", "rb") as f:
			data = f.read()
		
		self.emulator = Emulator(data)
		self.emulator.error.connect(self.handleError)
		self.emulator.breakpoint.connect(self.handleBreakpoint)
		
		self.error = False
		self.running = False
		
		self.timer = QTimer()
		self.timer.setInterval(20)
		self.timer.timeout.connect(self.stepTimer)
		self.timer.start()
	
	def initializeGeometry(self):
		"""Restores the window to its previous geometry."""
		
		geometry = self.settings.value("MainWindow.geometry")
		if geometry:
			self.restoreGeometry(geometry)
		else:
			screen = self.screen().size()
			self.setGeometry(
				screen.width() // 4, screen.height() // 4,
				screen.width() // 2, screen.height() // 2
			)
	
	def initializeWidgets(self):
		self.mainWidget = MainWidget(self.emulator)
		self.setCentralWidget(self.mainWidget)
		
		self.toolbar = ToolBar()
		self.toolbar.setObjectName("Toolbar")
		self.toolbar.setFloatable(False)
		self.toolbar.run.triggered.connect(self.handleRun)
		self.toolbar.step.triggered.connect(self.handleStep)
		self.toolbar.stop.triggered.connect(self.handleStop)
		self.toolbar.stop.setEnabled(False)
		self.addToolBar(self.toolbar)
		
		self.restoreState(self.settings.value("MainWindow.state", b""))
		self.mainWidget.restoreState(self.settings.value("MainWidget.state", b""))
	
	def closeEvent(self, e):
		self.settings.setValue("MainWindow.geometry", self.saveGeometry())
		self.settings.setValue("MainWindow.state", self.saveState())
		self.settings.setValue("MainWidget.state", self.mainWidget.saveState())
	
	def stepTimer(self):
		if self.running:
			self.emulator.run()
	
	def handleError(self, e):
		QMessageBox.information(self, "Error", e)
		self.toolbar.setEnabled(False)
		self.running = False
		self.error = True
	
	def handleBreakpoint(self):
		self.running = False
		self.toolbar.run.setEnabled(True)
		self.toolbar.step.setEnabled(True)
		self.toolbar.stop.setEnabled(False)
	
	def handleRun(self):
		self.running = True
		self.toolbar.run.setEnabled(False)
		self.toolbar.step.setEnabled(False)
		self.toolbar.stop.setEnabled(True)
	
	def handleStep(self):
		self.emulator.run(1)
	
	def handleStop(self):
		self.running = False
		self.toolbar.run.setEnabled(True)
		self.toolbar.step.setEnabled(True)
		self.toolbar.stop.setEnabled(False)


app = QApplication(sys.argv)
settings = QSettings("Yannik Marchand", "Skullcode Emulator")
window = MainWindow(settings)
window.show()
app.exec()
