
#pragma once

#include "system/texture.h"

#include <map>
#include <string>


class AssetLoader {
public:
    ~AssetLoader();

    Texture *texture(const std::string &name);

private:
    std::map<std::string, Texture *> textures;
};
