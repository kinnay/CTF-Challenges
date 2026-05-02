
#version 330
#extension GL_ARB_shader_storage_buffer_object : enable

// A work group always has 64 invocations (threads). Here, we can choose how we
// want to organize the invocations in a 3-dimensional space. Because our
// calculations are performed on a simple 1-dimensional buffer, we specify a
// (64 x 1 x 1) layout. This allows us to obtain the index of the invocation
// from its X coordinate.
//
// Note: our shader uses exactly one work group.
layout(local_size_x = 64, local_size_y = 1, local_size_z = 1) in;

// The uniform block contains data that is passed from the CPU to the GPU
layout(std140) uniform params {
    ivec4 key; // Hardcoded key for decrypting the flag verification matrix
    ivec4 inp; // Serialized player input

    // The following array contains various constants, such as the AES S-Box.
    // 
    // Initially, I attempted to embed these constants in the shader as a
    // 'const' array, but this led to errors about insufficient GPRs from the
    // shader compiler. Therefore, the constants are now provided by the CPU in
    // the uniform block.
    //
    // Warning: the shader compiler assumes that every array element has a
    // stride of 16 bytes, even if it is just a uint. It generates incorrect
    // code when a uint array is used. This is fixed by declaring an ivec4
    // array, even when uint would be more logical.
    //
    // Byte offsets:
    // 0x0: AES S-Box
    // 0x100: AES rcon table
    // 0x200: Table for multiplication by 2 in GF(2^8) for AES
    // 0x300: Table for multiplication by 3 in GF(2^8) for AES
    // 0x400: Encrypted flag verification matrix (128x128 bits)
    // 0xC00: Expected matrix multiplication result (128 bits)
    // 0xC10: Encryption key for "try harder" message
    // 0xC20: Encrypted "try harder" message
    // 0xC30: Flag encrypted with correct player input
    // 0xC60: <end>
    ivec4 constants[0xC6];
};

// This is the shader export buffer, it can be used to access CPU memory from
// the GPU. We are using it to communicate the decrypted flag or "try harder"
// message back to the CPU.
//
// Note: the size of this buffer must be a multiple of 256 bytes.
layout(std140) buffer buf {
    ivec4 result[16];
};

// The following array is shared between invocations. It contains element per
// invocation that indicates whether the matrix rows that are validated by the
// invocation are correct.
shared ivec4 temp[64];

ivec4 unpack_word(int word) {
    return ivec4(
		word & 0xFF,
        (word >> 8) & 0xFF,
        (word >> 16) & 0xFF,
		uint(word) >> 24
    );
}

int pack_word(ivec4 word) {
    int val = word.x;
    val |= word.y << 8;
    val |= word.z << 16;
	val |= word.w << 24;
    return val;
}

// Warning: the shader compiler generates incorrect code when a uint variable is
// used as an array index. The fix is to use int instead of uint for the index
// variable.
//
// This function would also be a bit easier if we could use a uint array instead
// of an ivec4 array. Unfortunately, the compiler generates incorrect code when
// a uint array is used.
int getword(int index) {
    ivec4 vec = constants[index >> 2];

    int lane = index & 3;
    if (lane == 0) return vec.x;
    else if (lane == 1) return vec.y;
    else if (lane == 2) return vec.z;
    else {
        return vec.w;
    }
}

// This function reads a specific byte from the constant array.
int getbyte(int index) {
	int word = getword(index >> 2);
	return (word >> ((index & 3) << 3)) & 0xFF;
}

// This function reads a specific bit from the constant array.
int getbit(int index, int bit) {
	return (getbyte(index) >> (7 - bit)) & 1;
}

int sbox(int val) {
	return getbyte(val);
}

int rcon(int val) {
	return getbyte(val + 0x100);
}

int mul2(int val) {
    return getbyte(val + 0x200);
}

int mul3(int val) {
    return getbyte(val + 0x300);
}

int rot_word(int word) {
    return pack_word(unpack_word(word).yzwx);
}

int sub_word(int word) {
    ivec4 v = unpack_word(word);
    return pack_word(ivec4(
        sbox(v.x), sbox(v.y),
        sbox(v.z), sbox(v.w)
    ));
}

ivec4 expand_key(ivec4 key, int round) {
    int c1 = sub_word(rot_word(key.w)) ^ key.x ^ rcon(round);
    int c2 = c1 ^ key.y;
    int c3 = c2 ^ key.z;
    int c4 = c3 ^ key.w;
    return ivec4(c1, c2, c3, c4);
}

ivec4 sub_bytes(ivec4 data) {
    return ivec4(
        sub_word(data.x),
        sub_word(data.y),
        sub_word(data.z),
        sub_word(data.w)
    );
}

ivec4 shift_rows(ivec4 data) {
    ivec4 c1 = unpack_word(data.x);
    ivec4 c2 = unpack_word(data.y);
    ivec4 c3 = unpack_word(data.z);
    ivec4 c4 = unpack_word(data.w);

    return ivec4(
        pack_word(ivec4(c1.x, c2.y, c3.z, c4.w)),
        pack_word(ivec4(c2.x, c3.y, c4.z, c1.w)),
        pack_word(ivec4(c3.x, c4.y, c1.z, c2.w)),
        pack_word(ivec4(c4.x, c1.y, c2.z, c3.w))
    );
}

int mix_column(int val) {
    ivec4 data = unpack_word(val);
    return pack_word(ivec4(
        mul2(data.x) ^ mul3(data.y) ^ data.z ^ data.w,
        data.x ^ mul2(data.y) ^ mul3(data.z) ^ data.w,
        data.x ^ data.y ^ mul2(data.z) ^ mul3(data.w),
        mul3(data.x) ^ data.y ^ data.z ^ mul2(data.w)
    ));
}

ivec4 mix_columns(ivec4 data) {
    return ivec4(
        mix_column(data.x),
        mix_column(data.y),
        mix_column(data.z),
        mix_column(data.w)
    );
}

ivec4 encrypt_aes(ivec4 key, ivec4 block) {
    // This method encrypts a block with AES-ECB.
    //
    // Note: this function is actually used to "decrypt" data, such as the flag.
    // For CTR mode, we need an AES encryption routine regardless of whether we
    // are encrypting or decrypting data. Reusing this method for flag
    // decryption saves the cost of implementing a separate AES decryption
    // routine.

	ivec4 round_key = key;
    block ^= round_key;
	
    for (int i = 0; i < 9; i++) {
		round_key = expand_key(round_key, i + 1);
        block = mix_columns(shift_rows(sub_bytes(block)));
        block ^= round_key;
	}
	
	round_key = expand_key(round_key, 10);
	block = shift_rows(sub_bytes(block));
	block ^= round_key;
	return block;
}

int count_bits(int val) {
    // Efficient algorithm that counts the hamming weight of val. The bitCount
    // function does not seem to be available, because it requires the
    // GL_ARB_gpu_shader5 extension, which is not supported by the compiler.
    //
    // We try to use uint as little as possible in the shader because it
    // triggers compiler bugs, but here we need it because we want logical
    // shifts instead of arithmetic shifts.
    uint uval = uint(val);
	uval = (uval & 0x55555555) + ((uval >> 1) & 0x55555555);
	uval = (uval & 0x33333333) + ((uval >> 2) & 0x33333333);
	uval = (uval & 0x0F0F0F0F) + ((uval >> 4) & 0x0F0F0F0F);
	uval = (uval & 0x00FF00FF) + ((uval >> 8) & 0x00FF00FF);
	uval = (uval & 0x0000FFFF) + ((uval >> 16) & 0x0000FFFF);
	return int(uval);
}

int check_row(int index) {
    // Checks whether a specific row of the matrix is correct. This function
    // decrypts the corresponding matrix row with AES-CTR with a hardcoded nonce
    // and the key that was received from the CPU. It then calculates the dot
    // product of the matrix row and the player input modulo 2. Returns whether
    // the result is correct.

    // Note: the nonce has byte swapped words here because the GPU is little
    // endian, unlike the CPU.
	ivec4 nonce = ivec4(0x19e81a72u, 0xe92c1c08u, 0xcc4c7ca7u, index << 24);
	ivec4 mask = encrypt_aes(key, nonce);
	
	ivec4 masked = (constants[0x40 + index] ^ mask) & inp;
	
	int result = count_bits(masked.x);
	result += count_bits(masked.y);
	result += count_bits(masked.z);
	result += count_bits(masked.w);
	
	return (result & 1) ^ getbit(0xC00 + index / 8, index % 8);
}

void main() {
    // The main function that verifies the player input.
    // 
    // Because our matrix has 128 rows, and there are 64 invocations in a work
    // group, every invocation verifies two rows of the matrix. If we used two
    // work groups instead of one, we would verify one row per invocation
    // instead. However, using multiple work groups makes it more difficult to
    // synchronize the results, so we only use a single work group in this
    // challenge.

    int index = int(gl_LocalInvocationIndex);
	
	int r1 = check_row(index * 2);
	int r2 = check_row(index * 2 + 1);
	
    // Store the result in shared memory so it can be accessed by the main
    // invocation later.
	temp[gl_LocalInvocationIndex] = r1 | r2;
	
    // The main invocation (with index 0) aggregates the results of all
    // invocations and, depending on the result, either decrypts the flag or the
    // "try harder" message.
    // 
    // Note: the GPU executes all invocations in a work group in lockstep.
    // Therefore, no barriers are needed here (no race conditions can occur).
	if (index == 0) {
		int final = 0;
        // Aggregate the results from shared memory
		for (int i = 0; i < 64; i++) {
			final |= temp[i].x;
		}
		
		if (final != 0) {
            // Decrypt the "try harder" message.
            result[0] = encrypt_aes(constants[0xC1], constants[0xC2]);
		}
		else {
            // Decrypt the flag using the player input as key.
			result[0] = encrypt_aes(inp, constants[0xC3]);
            result[1] = encrypt_aes(inp, constants[0xC4]);
            result[2] = encrypt_aes(inp, constants[0xC5]);
		}
	}
}
