
#include "system/texture.h"

#include <gfx/rio_PrimitiveRenderer.h>

#include <stdexcept>

Texture::Texture(const std::string &name) {
    texture = new rio::Texture2D(name.c_str());

    width = texture->getWidth();
    height = texture->getHeight();
}

Texture::~Texture() {
    delete texture;
}

void Texture::draw(float x, float y, float z, float rot, float scale) {
    rio::PrimitiveRenderer* const primitive_renderer = rio::PrimitiveRenderer::instance();

    // Set primitive renderer model matrix
    rio::Matrix34f rotation;
    rio::Matrix34f scale_and_translation;
    rio::Matrix34f model;

    rotation.makeR({0, 0, rot});
    scale_and_translation.makeST(
        { scale, scale, scale},
        {-640 + x + width / 2 * scale, -360 + y + height / 2 * scale, z}
    );
    model.setMul(scale_and_translation, rotation);

    primitive_renderer->setModelMatrix(model);

    primitive_renderer->drawQuad(
        *texture,
        rio::PrimitiveRenderer::QuadArg().setSize({width, height})
    );
}
