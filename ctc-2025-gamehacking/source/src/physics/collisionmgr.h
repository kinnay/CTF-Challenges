
#pragma once

#include "physics/collider.h"

#include <vector>

class CollisionMgr {
public:
    void add(Collider *collider);
    void remove(Collider *collider);

    void update();

private:
    std::vector<Collider *> colliders;
};
