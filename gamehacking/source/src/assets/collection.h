
#pragma once

#include "assets/stream.h"

#include <format>
#include <map>
#include <ranges>
#include <stdexcept>
#include <string>

class Archive;

template <class T>
class ResourceCollection {
public:
    ~ResourceCollection() {
        for (T *resource : resources | std::views::values) {
            delete resource;
        }
    }

    void load(Stream *stream, Archive *archive) {
        size_t count = stream->u8();
        for (size_t i = 0; i < count; i++) {
            std::string name = stream->string();
            if (resources.contains(name)) {
                throw std::runtime_error(std::format("Resource already exists: {}", name));
            }
            resources[name] = new T(stream, archive);
        }
    }

    T *get(const std::string &name) {
        if (!resources.contains(name)) {
            throw std::runtime_error(std::format("Resource not found: {}", name));
        }
        return resources[name];
    }

private:
    std::map<std::string, T *> resources;
};
