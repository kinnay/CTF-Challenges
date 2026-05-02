
#pragma once

#include "common/refcountedobj.h"

#include <string>

#include <cstddef>
#include <cstdint>

class Buffer : public RefCountedObj {
public:
	Buffer();
	Buffer(size_t size);
	Buffer(const void *data, size_t size);
	
	~Buffer();

	Ref<Buffer> copy();

	uint8_t *get();
	size_t size();

	void write(size_t offset, const void *data, size_t size);

	void resize(size_t size);

	std::string tostring();
	std::string hexstring();

private:
	uint8_t *data;
	size_t length;
	size_t capacity;
};
