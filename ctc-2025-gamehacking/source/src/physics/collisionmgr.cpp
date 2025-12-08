
#include "physics/collisionmgr.h"

void CollisionMgr::add(Collider *collider) {
    colliders.push_back(collider);
}

void CollisionMgr::remove(Collider *collider) {
    colliders.erase(std::find(colliders.begin(), colliders.end(), collider));
}

void CollisionMgr::update() {
    for (size_t i = 0; i < colliders.size(); i++) {
        Collider *collider1 = colliders[i];
        if (!collider1->passive) {
            for (size_t j = 0; j < colliders.size(); j++) {
                Collider *collider2 = colliders[j];
                if (collider2->passive || j > i) {
                    Collider::Side side1 = collider1->check(collider2);
                    Collider::Side side2 = collider2->check(collider1);
                    if (side1 != Collider::None) collider1->handle(collider2, side1);
                    if (side2 != Collider::None) collider2->handle(collider1, side2);
                }
            }
        }
    }
}
