
#include "common/filestreamin.h"
#include "common/fileutils.h"
#include "common/buffer.h"

#include <cstdio>

Ref<Buffer> FileUtils::load(std::string filename) {
	FileStreamIn stream(filename);
	return stream.read(stream.size());
}
