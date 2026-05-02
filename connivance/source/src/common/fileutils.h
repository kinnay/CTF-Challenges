
#pragma once

#include "common/buffer.h"
#include <string>

class FileUtils {
public:
	static Ref<Buffer> load(std::string filename);
};
