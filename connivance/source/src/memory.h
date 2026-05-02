
#pragma once

#include <cstddef>
#include <cstdint>

struct Segment {
	size_t base;
	size_t size;
};

struct MapFile {
	uint64_t text_size;
	uint64_t rodata_size;
	uint8_t text_hash[32];
	uint8_t rodata_hash[32];
};

MapFile *get_map_file();

Segment get_text_segment();
Segment get_rodata_segment();

uint64_t get_text_base();
uint64_t get_rodata_base();

uint64_t get_text_size();
uint64_t get_rodata_size();

bool verify_hashes();
