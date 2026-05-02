
#pragma once

#include "common/buffer.h"

#include <vector>

#include <cstdint>


enum Opcode {
	OPCODE_INVERT_BUFFER = 1,
	OPCODE_CHECK_FILE_SIGNATURE = 2,

	OPCODE_PUSH_TEXT_BASE = 6,

	OPCODE_JUMP_IF_GE = 8,

	OPCODE_PUSH_RODATA_SIZE = 12,
	OPCODE_PUSH_BUFFER_SIZE = 13,

	OPCODE_CHECK_BUFFER_SIGNATURE = 16,
	
	OPCODE_POP_VAR = 21,
	OPCODE_DECRYPT_AES_128_ECB = 22,
	OPCODE_COMPARE = 23,
	OPCODE_POP_BUFFER = 24,
	OPCODE_APPEND_VALUE = 25,

	OPCODE_JUMP_IF_EQ = 28,
	OPCODE_PUSH_VALUE = 29,
	OPCODE_PUSH_INPUT = 30,

	OPCODE_WRITE_OUTPUT_33 = 33,

	OPCODE_NOP_38 = 38,
	OPCODE_ALIGN_UP = 39,
	OPCODE_DECRYPT_PROGRAM = 40,

	OPCODE_SLICE_SECOND_HALF = 44,
	OPCODE_JUMP_IF_VALID = 45,

	OPCODE_JUMP_IF_NE = 47,
	OPCODE_JUMP_IF_INVALID = 48,

	OPCODE_GET_VAR = 53,

	OPCODE_CONCAT = 57,

	OPCODE_WRITE_OUTPUT_59 = 59,

	OPCODE_PUSH_RODATA_BASE = 61,

	OPCODE_ADD = 63,
	OPCODE_JUMP = 64,

	OPCODE_SHA256 = 66,

	OPCODE_NOP_69 = 69,

	OPCODE_PUSH_TEXT_SIZE = 74,
	OPCODE_PUSH_VAR = 75,

	OPCODE_NOP_78 = 78,
	OPCODE_LOAD_FILE = 79,
	OPCODE_DECRYPT_RSA_OAEP = 80,
	OPCODE_RSHIFT_BYTES = 81,

	OPCODE_SET_INVALID = 83,
	OPCODE_SLICE_FIRST_HALF = 84,

	OPCODE_PUSH_MEMORY = 87,
	OPCODE_CLEAR_BUFFER = 88,
	OPCODE_SLICE_BUFFER = 89,
	OPCODE_SET_VAR = 90,
	OPCODE_NEW_BUFFER = 91,

	OPCODE_LOAD_WHOLE_FILE = 94,
	OPCODE_LAST = 95
};


struct Instruction {
	uint16_t opcode;
	uint32_t param32;
	uint64_t param64;
};

struct VMState {
	uint64_t pc;
	Ref<Buffer> program;
	Ref<Buffer> memory;
	std::vector<Ref<Buffer>> stack;
	std::vector<Ref<Buffer>> variables;
	int comparison;
	bool invalid;

	void push(Ref<Buffer> buffer);
	void push(uint64_t value);
	
	Ref<Buffer> last();
	Ref<Buffer> pop();
	uint64_t pop_value();
	
	void setvar(size_t index, Ref<Buffer> buffer);
	Ref<Buffer> getvar(size_t index);
};

class VM {
public:
	typedef void (VM::*Callback)(Instruction *instr, VMState *state);

	VM();

	bool execute(Ref<Buffer> program, Ref<Buffer> memory);

private:
	void initialize_callbacks();

	void handle_decrypt_program(Instruction *instr, VMState *state);

	void handle_nop(Instruction *instr, VMState *state);

	void handle_new_buffer(Instruction *instr, VMState *state);
	void handle_pop_buffer(Instruction *instr, VMState *state);
	void handle_append_value(Instruction *instr, VMState *state);
	void handle_push_value(Instruction *instr, VMState *state);
	void handle_slice_first_half(Instruction *instr, VMState *state);
	void handle_slice_second_half(Instruction *instr, VMState *state);
	void handle_slice_buffer(Instruction *instr, VMState *state);
	void handle_push_buffer_size(Instruction *instr, VMState *state);
	void handle_clear_buffer(Instruction *instr, VMState *state);
	void handle_invert_buffer(Instruction *instr, VMState *state);
	void handle_rshift_bytes(Instruction *instr, VMState *state);
	void handle_concat(Instruction *instr, VMState *state);

	void handle_pop_var(Instruction *instr, VMState *state);
	void handle_push_var(Instruction *instr, VMState *state);
	void handle_set_var(Instruction *instr, VMState *state);
	void handle_get_var(Instruction *instr, VMState *state);

	void handle_push_input(Instruction *instr, VMState *state);
	void handle_write_output(Instruction *instr, VMState *state);

	void handle_push_text_base(Instruction *instr, VMState *state);
	void handle_push_text_size(Instruction *instr, VMState *state);
	void handle_push_rodata_base(Instruction *instr, VMState *state);
	void handle_push_rodata_size(Instruction *instr, VMState *state);
	void handle_push_memory(Instruction *instr, VMState *state);

	void handle_compare(Instruction *instr, VMState *state);
	void handle_add(Instruction *instr, VMState *state);

	void handle_align_up(Instruction *instr, VMState *state);

	void handle_jump(Instruction *instr, VMState *state);
	void handle_jump_if_valid(Instruction *instr, VMState *state);
	void handle_jump_if_invalid(Instruction *instr, VMState *state);
	void handle_jump_if_eq(Instruction *instr, VMState *state);
	void handle_jump_if_ne(Instruction *instr, VMState *state);
	void handle_jump_if_ge(Instruction *instr, VMState *state);

	void handle_set_invalid(Instruction *instr, VMState *state);

	void handle_load_file(Instruction *instr, VMState *state);
	void handle_load_whole_file(Instruction *instr, VMState *state);
	void handle_check_file_signature(Instruction *instr, VMState *state);

	void handle_check_buffer_signature(Instruction *instr, VMState *state);

	void handle_decrypt_aes_128_ecb(Instruction *instr, VMState *state);

	void handle_decrypt_rsa_oaep(Instruction *instr, VMState *state);

	void handle_sha256(Instruction *instr, VMState *state);

	Callback callbacks[OPCODE_LAST];
};
