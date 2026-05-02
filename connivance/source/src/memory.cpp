
#include "common/buffer.h"
#include "common/fileutils.h"

#include "crypto.h"
#include "files.h"
#include "memory.h"

#include <mbedtls/sha256.h>

#include <cstdlib>
#include <cstring>

MapFile *map_file = nullptr;

void addr_in_text_segment() {}
const char addr_in_rodata_segment[] = {0};

void parse_hex(const char **ptr, uint64_t *value) {
	const char *p = *ptr;

	*value = 0;
	while (true) {
		char c = *p;
		if (c >= '0' && c <= '9') {
			*value = (*value << 4) | (c - '0');
		}
		else if (c >= 'a' && c <= 'f') {
			*value = (*value << 4) | (c - 'a' + 10);
		}
		else {
			*ptr = p;
			return;
		}
		*p++;
	}
}

bool parse_line(const char *ptr, Segment *segment) {
	if (!*ptr) {
		return false;
	}

	uint64_t start, end;
	parse_hex(&ptr, &start);
	*ptr++;
	parse_hex(&ptr, &end);

	segment->base = start;
	segment->size = end - start;

	while (*ptr++ != '\n');
	return true;
}

Segment find_segment(size_t address) {
	FILE *f = fopen("/proc/self/maps", "r");

	char *line = nullptr;
	size_t size;
	Segment segment;

	while (getline(&line, &size, f) != -1) {
		parse_line(line, &segment);
		if (segment.base <= address && segment.base + segment.size > address) {
			return segment;
		}
	}

	return Segment();
}

void load_map_file() {
	map_file = (MapFile *)malloc(sizeof(MapFile));
	Ref<Buffer> data = load_file("romfs:/map");
	memcpy(map_file, data->get(), data->size());
}

MapFile *get_map_file() {
	if (!map_file) {
		load_map_file();
	}
	return map_file;
}

Segment get_text_segment() {
	return find_segment((size_t)addr_in_text_segment);
}

Segment get_rodata_segment() {
	return find_segment((size_t)addr_in_rodata_segment);
}

uint64_t get_text_base() {
	return get_text_segment().base;
}

uint64_t get_rodata_base() {
	return get_rodata_segment().base;
}

uint64_t get_text_size() {
	return get_map_file()->text_size;
}

uint64_t get_rodata_size() {
	return get_map_file()->rodata_size;
}

bool verify_hashes() {
	uint8_t hash[32];
	MapFile *map_file = get_map_file();

	uint64_t base = get_text_base();
	uint64_t size = get_text_size();
	mbedtls_sha256((const uint8_t *)base, size, hash, false);
	
	if (memcmp(hash, map_file->text_hash, 32)) {
		return true;
	}

	base = get_rodata_base();
	size = get_rodata_size();
	mbedtls_sha256((const uint8_t *)base, size, hash, false);
	
	if (memcmp(hash, map_file->rodata_hash, 32)) {
		return true;
	}
	return false;
}
