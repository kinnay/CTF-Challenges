
#include "assetloader.h"

#include "system/texture.h"

#include <ranges>


AssetLoader::~AssetLoader() {
    for (Texture *texture : textures | std::views::values) {
        delete texture;
    }
}

Texture *AssetLoader::texture(const std::string &name) {
    if (!textures.contains(name)) {
        textures[name] = new Texture(name);
    }
    return textures[name];
}
