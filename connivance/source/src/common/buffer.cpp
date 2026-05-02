
#include "common/buffer.h"
#include "common/exceptions.h"
#include "common/stringutils.h"

#include <cstdlib>
#include <cstring>


Buffer::Buffer() {
	data = nullptr;
	length = 0;
	capacity = 0;
}

Buffer::Buffer(size_t size) {
	this->data = (uint8_t *)malloc(size);
	memset(this->data, 0, size);

	length = size;
	capacity = size;
}

Buffer::Buffer(const void *data, size_t size) {
	this->data = (uint8_t *)malloc(size);
	memcpy(this->data, data, size);

	length = size;
	capacity = size;
}

Buffer::~Buffer() {
	if (data) {
		free(data);
	}
}

Ref<Buffer> Buffer::copy() {
	return new Buffer(data, length);
}

uint8_t *Buffer::get() {
	return data;
}

size_t Buffer::size() {
	return length;
}

void Buffer::write(size_t offset, const void *data, size_t size) {
	if (size > length || length - size < offset) {
		runtime_error("Overflow in Buffer::write");
	}
	memcpy(this->data + offset, data, size);
}

void Buffer::resize(size_t size) {
	if (size > capacity) {
		data = (uint8_t *)realloc(data, size);
		capacity = size;
	}
	length = size;
}

std::string Buffer::tostring() {
	return std::string((const char *)get(), size());
}

std::string Buffer::hexstring() {
	std::string s;
	for (size_t i = 0; i < length; i++) {
		s += StringUtils::format("%02x", data[i]);
	}
	return s;
}
