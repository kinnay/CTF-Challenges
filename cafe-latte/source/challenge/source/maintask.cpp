
#include "maintask.h"

#include "app.h"

#include <controller/rio_ControllerMgr.h>
#include <gfx/rio_Camera.h>
#include <gfx/rio_PrimitiveRenderer.h>
#include <gfx/rio_Projection.h>
#include <gfx/rio_Window.h>
#include <gpu/rio_RenderState.h>
#include <math/rio_Matrix.h>

#include <sndcore2/core.h>

MainTask::MainTask() : ITask("MainTask")
{
}

void MainTask::prepare_()
{
    AXInit(); // This stops the Wii U loading sound from playing

    app = new App();

    // Create layer
    mLayer.it = rio::lyr::Renderer::instance()->addLayer("Layer");
    mLayer.ptr = rio::lyr::Layer::peelIterator(mLayer.it);
    // Clear color buffer before the layer is drawn
    mLayer.ptr->setClearColor({ 0.0f, 0.0f, 0.0f, 1.0f });
    // Clear depth-stencil buffer before the layer is drawn
    mLayer.ptr->setClearDepthStencil();
    // Add render step and draw method
    mLayer.ptr->addRenderStep("Layer");
    mLayer.ptr->addDrawMethod(0, { this, &MainTask::render });

    // Set primitive renderer camera and projection
    rio::PrimitiveRenderer::instance()->setCamera(*mLayer.ptr->camera());
    rio::PrimitiveRenderer::instance()->setProjection(*mLayer.ptr->projection());
}

void MainTask::exit_()
{
    delete app;
}

void MainTask::calc_() {
    app->update();
}

void MainTask::render(const rio::lyr::DrawInfo& draw_info)
{
    // Restore default GPU state
    rio::RenderState render_state;
    render_state.apply();
    
    rio::PrimitiveRenderer::instance()->begin();
    app->draw();
    rio::PrimitiveRenderer::instance()->end();
}
