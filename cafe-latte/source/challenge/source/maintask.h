
#pragma once

#include "app.h"

#include <controller/rio_Controller.h>
#include <gfx/lyr/rio_Renderer.h>
#include <gpu/rio_Texture.h>
#include <task/rio_Task.h>

class MainTask : public rio::ITask, public rio::lyr::IDrawable
{
public:
    MainTask();

    void render(const rio::lyr::DrawInfo&);

private:
    void prepare_() override;
    void calc_() override;
    void exit_() override;

private:
    struct
    {
        rio::lyr::Layer::iterator   it;
        rio::lyr::Layer*            ptr;
    } mLayer;

    App *app;
};
