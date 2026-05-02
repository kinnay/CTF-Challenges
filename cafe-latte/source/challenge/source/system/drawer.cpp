
#include "drawer.h"

#include <gfx/rio_PrimitiveRenderer.h>


void Drawer::rectangle(float x, float y, float w, float h, float r, float g, float b, float z) {
    rio::PrimitiveRenderer* const primitive_renderer = rio::PrimitiveRenderer::instance();

    primitive_renderer->setModelMatrix(rio::Matrix34f::ident);
    primitive_renderer->drawQuad(
        rio::PrimitiveRenderer::QuadArg()
            .setColor({r, g, b, 1})
            .setCornerAndSize({x - 640, y - 360, z}, {w, h})
    );
}
