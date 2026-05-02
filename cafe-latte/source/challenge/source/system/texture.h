
#pragma once

#include <gpu/rio_Texture.h>

#include <string>


class Texture {
public:
    Texture(const std::string &name);
    ~Texture();

    void draw(float x, float y, float z, float rot = 0, float scale = 1);

    float width;
    float height;

private:
    rio::Texture2D* texture;
};
