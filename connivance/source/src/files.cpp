
#include "files.h"

#include "common/exceptions.h"
#include "common/fileutils.h"


Ref<Buffer> load_file(std::string url) {
	size_t pos = url.find(":/");

	std::string scheme = url.substr(0, pos);
	std::string path = url.substr(pos + 2);
	if (scheme == "romfs") {
		return FileUtils::load("romfs/" + path);
	}
	runtime_error("Unimplemented scheme: %s", scheme);
	return nullptr;
}
