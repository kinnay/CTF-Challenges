
#include "common/buffer.h"
#include "common/fileutils.h"

#include "crypto.h"
#include "files.h"
#include "memory.h"
#include "vm.h"

#include <mbedtls/sha256.h>

#include <cstdio>
#include <cstring>


bool decrypt_buffer(Ref<Buffer> buffer) {
	Ref<Buffer> connivance = load_file("romfs:/connivance.bin");

	uint8_t *signature = connivance->get();
	uint8_t *program = connivance->get() + 256;
	size_t program_size = connivance->size() - 256;

	uint8_t key[32];
	mbedtls_sha256((const uint8_t *)"dilate", 6, key, false);
	decrypt_aes_ctr(program, program_size, key + 16, 4096);

	if (verify_standard_signature(program, program_size, signature)) {
		return true;
	}

	VM vm;
	return vm.execute(new Buffer(program, program_size), buffer);
}

int main(int argc, const char *argv[]) {
	if (verify_hashes()) {
		return 1;
	}

	if (argc < 2) {
		printf("Usage: ./main flag_checker.tfl <flag>\n");
		return 1;
	}

	Ref<Buffer> program = FileUtils::load(argv[1]);
	if (decrypt_buffer(program)) {
		printf("Program decryption failed\n");
		return 1;
	}

	Ref<Buffer> memory;
	if (argc > 2) {
		memory = new Buffer(argv[2], strlen(argv[2]));
	}
	else {
		memory = new Buffer();
	}

	VM vm;
	if (vm.execute(program, memory)) {
		printf("Program execution failed\n");
		return 1;
	}

	std::string output = memory->tostring();
	printf("%s\n", output.c_str());
	return 0;
}
