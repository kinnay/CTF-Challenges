
#include "vm.h"

#include "common/buffer.h"
#include "common/endian.h"

#include "crypto.h"
#include "files.h"
#include "memory.h"

#include <mbedtls/bignum.h>
#include <mbedtls/sha256.h>

#include <cstdint>
#include <cstring>


void buffer_to_mpi(Ref<Buffer> buffer, mbedtls_mpi *mpi) {
	mbedtls_mpi_init(mpi);
	mbedtls_mpi_read_binary_le(mpi, buffer->get(), buffer->size());
}

void mpi_to_buffer(Ref<Buffer> buffer, mbedtls_mpi *mpi) {
	buffer->resize(mbedtls_mpi_size(mpi));
	mbedtls_mpi_write_binary_le(mpi, buffer->get(), buffer->size());
}

void VMState::push(Ref<Buffer> buffer) {
	stack.push_back(buffer);
}

void VMState::push(uint64_t value) {
	push(new Buffer(&value, 8));
}

Ref<Buffer> VMState::last() {
	if (stack.size() == 0) {
		return new Buffer();
	}
	return stack.back();
}

Ref<Buffer> VMState::pop() {
	if (stack.size() == 0) {
		return new Buffer();
	}
	Ref<Buffer> buffer = stack.back();
	stack.pop_back();
	return buffer;
}

uint64_t VMState::pop_value() {
	if (stack.size() == 0) {
		return 0;
	}

	uint64_t value = 0;
	Ref<Buffer> buffer = pop();
	size_t size = buffer->size();
	memcpy(&value, buffer->get(), size > 8 ? 8 : size);
	return value;
}

void VMState::setvar(size_t index, Ref<Buffer> buffer) {
	if (index >= variables.size()) {
		variables.resize(index + 1);
	}
	variables[index] = buffer;
}

Ref<Buffer> VMState::getvar(size_t index) {
	return variables[index];
}


VM::VM() {
	initialize_callbacks();
}

bool VM::execute(Ref<Buffer> program, Ref<Buffer> memory) {
	VMState state;
	state.pc = 0;
	state.program = program;
	state.memory = memory;
	state.comparison = 0;
	state.invalid = false;

	while (state.pc < program->size() / 16) {
		Instruction *instr = (Instruction *)program->get() + state.pc;
		if (instr->opcode >= OPCODE_LAST) {
			return true;
		}
		Callback callback = callbacks[instr->opcode];
		if (!callback) {
			return true;
		}
		(this->*callback)(instr, &state);
		state.pc++;
	}
	return state.invalid;
}

void VM::initialize_callbacks() {
	memset(callbacks, 0, sizeof(callbacks));

	callbacks[OPCODE_RSHIFT_BYTES] = &VM::handle_rshift_bytes;
	callbacks[OPCODE_CLEAR_BUFFER] = &VM::handle_clear_buffer;
	callbacks[OPCODE_INVERT_BUFFER] = &VM::handle_invert_buffer;
	callbacks[OPCODE_PUSH_BUFFER_SIZE] = &VM::handle_push_buffer_size;
	callbacks[OPCODE_SLICE_FIRST_HALF] = &VM::handle_slice_first_half;
	callbacks[OPCODE_SLICE_SECOND_HALF] = &VM::handle_slice_second_half;
	callbacks[OPCODE_SLICE_BUFFER] = &VM::handle_slice_buffer;
	callbacks[OPCODE_NOP_38] = &VM::handle_nop;
	callbacks[OPCODE_COMPARE] = &VM::handle_compare;
	callbacks[OPCODE_SET_INVALID] = &VM::handle_set_invalid;
	callbacks[OPCODE_JUMP_IF_INVALID] = &VM::handle_jump_if_invalid;
	callbacks[OPCODE_JUMP_IF_VALID] = &VM::handle_jump_if_valid;
	callbacks[OPCODE_JUMP_IF_EQ] = &VM::handle_jump_if_eq;
	callbacks[OPCODE_NOP_78] = &VM::handle_nop;
	callbacks[OPCODE_JUMP] = &VM::handle_jump;
	callbacks[OPCODE_JUMP_IF_NE] = &VM::handle_jump_if_ne;
	callbacks[OPCODE_JUMP_IF_GE] = &VM::handle_jump_if_ge;
	// jump if greater or equal
	// jump if smaller
	// jump if smaller or equal
	callbacks[OPCODE_NEW_BUFFER] =  &VM::handle_new_buffer;
	// dup buffer
	callbacks[OPCODE_PUSH_VALUE] = &VM::handle_push_value;
	callbacks[OPCODE_APPEND_VALUE] = &VM::handle_append_value;
	callbacks[OPCODE_POP_BUFFER] = &VM::handle_pop_buffer;
	// append value
	callbacks[OPCODE_PUSH_INPUT] = &VM::handle_push_input;
	callbacks[OPCODE_WRITE_OUTPUT_33] = &VM::handle_write_output;
	callbacks[OPCODE_GET_VAR] = &VM::handle_get_var;
	callbacks[OPCODE_PUSH_VAR] = &VM::handle_push_var;
	callbacks[OPCODE_SET_VAR] = &VM::handle_set_var;
	callbacks[OPCODE_POP_VAR] = &VM::handle_pop_var;
	// resize buffer
	callbacks[OPCODE_CONCAT] = &VM::handle_concat;
	callbacks[OPCODE_WRITE_OUTPUT_59] = &VM::handle_write_output;
	// decrypt rsa
	// unpad oaep
	callbacks[OPCODE_DECRYPT_RSA_OAEP] = &VM::handle_decrypt_rsa_oaep;
	callbacks[OPCODE_DECRYPT_AES_128_ECB] = &VM::handle_decrypt_aes_128_ecb;
	// encrypt aes 128 ecb
	// decrypt aes 256 ecb
	// encrypt aes 256 ecb
	// decrypt aes 128 ctr
	// encrypt aes 128 ctr
	// decrypt aes 256 ctr
	// encrypt aes 256 ctr
	callbacks[OPCODE_SHA256] = &VM::handle_sha256;
	callbacks[OPCODE_ADD] = &VM::handle_add;
	// add buffer
	// sub
	// mul
	// mod
	// div
	callbacks[OPCODE_ALIGN_UP] =  &VM::handle_align_up;
	// lshift
	// rshift
	// unknown
	// print error
	// print message
	callbacks[OPCODE_CHECK_FILE_SIGNATURE] = &VM::handle_check_file_signature;
	callbacks[OPCODE_CHECK_BUFFER_SIGNATURE] = &VM::handle_check_buffer_signature;
	// connect ipc
	// unknown
	// unknown
	// unknown
	// nop 54
	callbacks[OPCODE_NOP_69] = &VM::handle_nop;
	callbacks[OPCODE_LOAD_FILE] = &VM::handle_load_file;
	callbacks[OPCODE_LOAD_WHOLE_FILE] = &VM::handle_load_whole_file;
	callbacks[OPCODE_PUSH_TEXT_SIZE] = &VM::handle_push_text_size;
	callbacks[OPCODE_PUSH_RODATA_SIZE] = &VM::handle_push_rodata_size;
	// push partial rodata size
	// push partial rodata size
	callbacks[OPCODE_PUSH_TEXT_BASE] = &VM::handle_push_text_base;
	callbacks[OPCODE_PUSH_RODATA_BASE] = &VM::handle_push_rodata_base;
	// push rodata base 2
	// push rodata base 2
	callbacks[OPCODE_PUSH_MEMORY] = &VM::handle_push_memory;
	callbacks[OPCODE_DECRYPT_PROGRAM] = &VM::handle_decrypt_program;
	// rotate opcodes
	// nop 19
	// unknown
}

void VM::handle_decrypt_program(Instruction *instr, VMState *state) {
	uint8_t key[32];

	mbedtls_sha256((uint8_t *)&instr->param64, 8, key, false);

	Ref<Buffer> buffer = state->program;

	uint8_t *start = buffer->get() + state->pc * 16 + 16;
	size_t size = buffer->size() - state->pc * 16 - 16;

	decrypt_aes_ctr(start, size, key, 0x2AF06007DD731AAC);
}

void VM::handle_nop(Instruction *instr, VMState *state) {
}

void VM::handle_new_buffer(Instruction *instr, VMState *state) {
	state->push(new Buffer());
}

void VM::handle_pop_buffer(Instruction *instr, VMState *state) {
	state->pop();
}

void VM::handle_append_value(Instruction *instr, VMState *state) {
	Ref<Buffer> buffer = state->last();
	buffer->resize(buffer->size() + 8);
	buffer->write(buffer->size() - 8, &instr->param64, 8);
}

void VM::handle_push_value(Instruction *instr, VMState *state) {
	state->push(instr->param64);
}

void VM::handle_slice_first_half(Instruction *instr, VMState *state) {
	Ref<Buffer> buffer = state->last();
	Ref<Buffer> slice = new Buffer(buffer->get(), buffer->size() / 2);
	state->push(slice);
}

void VM::handle_slice_second_half(Instruction *instr, VMState *state) {
	Ref<Buffer> buffer = state->last();

	size_t offset = buffer->size() / 2;

	Ref<Buffer> slice = new Buffer(buffer->get() + offset, buffer->size() - offset);
	state->push(slice);
}

void VM::handle_slice_buffer(Instruction *instr, VMState *state) {
	uint64_t size = state->pop_value();
	uint64_t offset = state->pop_value();

	Ref<Buffer> buffer = state->last();
	Ref<Buffer> result = new Buffer();
	if (offset < buffer->size() && buffer->size() - offset >= size) {
		result = new Buffer(buffer->get() + offset, size);
	}
	state->push(result);
}

void VM::handle_push_buffer_size(Instruction *instr, VMState *state) {
	state->push(state->last()->size());
}

void VM::handle_clear_buffer(Instruction *instr, VMState *state) {
	state->last()->resize(0);
}

void VM::handle_invert_buffer(Instruction *instr, VMState *state) {
	Ref<Buffer> buffer = state->last();
	for (size_t i = 0; i < buffer->size(); i++) {
		buffer->get()[i] = ~buffer->get()[i];
	}
}

void VM::handle_rshift_bytes(Instruction *instr, VMState *state) {
	Ref<Buffer> buffer = state->last();
	for (size_t i = 0; i < buffer->size(); i++) {
		buffer->get()[i] >>= 1;
	}
}

void VM::handle_concat(Instruction *instr, VMState *state) {
	Ref<Buffer> a = state->pop();
	Ref<Buffer> b = state->last();
	size_t offset = b->size();
	b->resize(b->size() + a->size());
	memcpy(b->get() + offset, a->get(), a->size());
}

void VM::handle_pop_var(Instruction *instr, VMState *state) {
	state->setvar(instr->param64, state->pop());
}

void VM::handle_push_var(Instruction *instr, VMState *state) {
	state->push(state->getvar(instr->param64)->copy());
}

void VM::handle_set_var(Instruction *instr, VMState *state) {
	state->setvar(instr->param64, state->last()->copy());
}

void VM::handle_get_var(Instruction *instr, VMState *state) {
	Ref<Buffer> dest = state->last();
	Ref<Buffer> source = state->getvar(instr->param64);
	dest->resize(source->size());
	memcpy(dest->get(), source->get(), source->size());
}

void VM::handle_push_input(Instruction *instr, VMState *state) {
	state->push(state->memory->copy());
}

void VM::handle_write_output(Instruction *instr, VMState *state) {
	Ref<Buffer> data = state->last();
	state->memory->resize(data->size());
	memcpy(state->memory->get(), data->get(), data->size());
}

void VM::handle_push_text_base(Instruction *instr, VMState *state) {
	state->push(get_text_base());
}

void VM::handle_push_text_size(Instruction *instr, VMState *state) {
	state->push(get_text_size());
}

void VM::handle_push_rodata_base(Instruction *instr, VMState *state) {
	state->push(get_rodata_base());
}

void VM::handle_push_rodata_size(Instruction *instr, VMState *state) {
	MapFile *map = get_map_file();
	state->push(get_rodata_size());
}

void VM::handle_push_memory(Instruction *instr, VMState *state) {
	uint64_t size = state->pop_value();
	uint64_t base = state->pop_value();
	Ref<Buffer> buffer = new Buffer((const void *)base, size);
	state->push(buffer);
}

void VM::handle_align_up(Instruction *instr, VMState *state) {
	uint64_t value = state->pop_value();
	if (value % instr->param64) {
		value += instr->param64 - value % instr->param64;
	}
	state->push(value);
}

void VM::handle_compare(Instruction *instr, VMState *state) {
	Ref<Buffer> bufa = state->getvar(instr->param64);
	Ref<Buffer> bufb = state->getvar(instr->param32);

	mbedtls_mpi a, b;
	buffer_to_mpi(bufa, &a);
	buffer_to_mpi(bufb, &b);

	state->comparison = mbedtls_mpi_cmp_mpi(&a, &b);

	mbedtls_mpi_free(&a);
	mbedtls_mpi_free(&b);
}

void VM::handle_add(Instruction *instr, VMState *state) {
	Ref<Buffer> srcbuf = state->pop();
	Ref<Buffer> dstbuf = state->getvar(instr->param64);

	mbedtls_mpi src, dst;
	buffer_to_mpi(srcbuf, &src);
	buffer_to_mpi(dstbuf, &dst);
	mbedtls_mpi_add_mpi(&dst, &src, &dst);
	mpi_to_buffer(dstbuf, &dst);

	mbedtls_mpi_free(&src);
	mbedtls_mpi_free(&dst);
}

void VM::handle_jump(Instruction *instr, VMState *state) {
	state->pc += instr->param64 - 1;
}

void VM::handle_jump_if_valid(Instruction *instr, VMState *state) {
	if (!state->invalid) {
		state->pc += instr->param64 - 1;
	}
}

void VM::handle_jump_if_invalid(Instruction *instr, VMState *state) {
	if (state->invalid) {
		state->pc += instr->param64 - 1;
	}
}

void VM::handle_jump_if_eq(Instruction *instr, VMState *state) {
	if (state->comparison == 0) {
		state->pc += instr->param64 - 1;
	}
}

void VM::handle_jump_if_ne(Instruction *instr, VMState *state) {
	if (state->comparison != 0) {
		state->pc += instr->param64 - 1;
	}
}

void VM::handle_jump_if_ge(Instruction *instr, VMState *state) {
	if (state->comparison >= 0) {
		state->pc += instr->param64 - 1;
	}
}

void VM::handle_set_invalid(Instruction *instr, VMState *state) {
	state->invalid = true;
}

void VM::handle_load_file(Instruction *instr, VMState *state) {
	uint64_t size = state->pop_value();
	uint64_t offset = state->pop_value();
	Ref<Buffer> path_buffer = state->pop();

	std::string path = std::string((const char *)path_buffer->get());

	Ref<Buffer> data = load_file(path);
	if (size == 0) {
		size = data->size() - offset;
	}

	Ref<Buffer> slice = new Buffer(data->get() + offset, size);
	state->push(slice);
}

void VM::handle_load_whole_file(Instruction *instr, VMState *state) {
	Ref<Buffer> path_buffer = state->pop();
	std::string path = std::string((const char *)path_buffer->get());

	Ref<Buffer> data = load_file(path);
	state->push(data);
}

void VM::handle_check_file_signature(Instruction *instr, VMState *state) {
	Ref<Buffer> buffer = state->pop();

	std::string filename = std::string((const char *)buffer->get());
	std::string signature_filename = filename + ".sig";

	Ref<Buffer> file = load_file(filename);
	Ref<Buffer> signature = load_file(signature_filename);

	state->invalid = verify_standard_signature(file->get(), file->size(), signature->get());
}

void VM::handle_check_buffer_signature(Instruction *instr, VMState *state) {
	Ref<Buffer> signature = state->pop();
	Ref<Buffer> buffer = state->pop();

	state->invalid = verify_standard_signature(buffer->get(), buffer->size(), signature->get());
}

void VM::handle_decrypt_aes_128_ecb(Instruction *instr, VMState *state) {
	Ref<Buffer> key = state->pop();
	Ref<Buffer> data = state->last();
	decrypt_aes_ecb(data->get(), data->size(), key->get());
}

void VM::handle_decrypt_rsa_oaep(Instruction *instr, VMState *state) {
	Ref<Buffer> nbuf = state->pop();
	Ref<Buffer> dbuf = state->pop();
	Ref<Buffer> databuf = state->last();

	size_t size = 0;
	if (nbuf->size() == 256 && dbuf->size() == 256 && databuf->size() == 256) {
		size = decrypt_rsa_oaep(databuf->get(), nbuf->get(), dbuf->get());
	}
	
	state->comparison = size;
	state->invalid = size == 0;
}

void VM::handle_sha256(Instruction *instr, VMState *state) {
	Ref<Buffer> data = state->last();

	uint8_t hash[32];
	mbedtls_sha256(data->get(), data->size(), hash, false);

	state->push(new Buffer(hash, 32));
}
