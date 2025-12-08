
#include "physics/collider.h"

#include "actors/actor.h"

#include <algorithm>

Collider::Collider(Actor *owner, double w, double h) : Collider(owner, 0, 0, w, h) {}

Collider::Collider(Actor *owner, double x, double y, double w, double h) {
    this->owner = owner;
    this->x = x;
    this->y = y;
    this->w = w;
    this->h = h;

    passive = false;
}

double Collider::left() { return owner->position.x + x; }
double Collider::right() { return left() + w; }
double Collider::top() { return owner->position.y + y; }
double Collider::bottom() { return top() + h; }

void Collider::move_left(double pos) { owner->position.x = pos - x; }
void Collider::move_right(double pos) { owner->position.x = pos - x - w; }
void Collider::move_top(double pos) { owner->position.y = pos - y; }
void Collider::move_bottom(double pos) { owner->position.y = pos - y - h; }

bool Collider::intersects(Collider *other) {
    return left() <= other->right() && right() >= other->left() &&
        top() <= other->bottom() && bottom() >= other->top();
}

Collider::Side Collider::check(Collider *other) {
    if (!intersects(other)) {
        return Collider::None;
    }

    double ldist = other->right() - left();
    double rdist = right() - other->left();
    double tdist = other->bottom() - top();
    double bdist = bottom() - other->top();

    double mindist = std::min(ldist, rdist);
    mindist = std::min(mindist, tdist);
    mindist = std::min(mindist, bdist);

    if (mindist == bdist) return Collider::Bottom;
    if (mindist == ldist) return Collider::Left;
    if (mindist == rdist) return Collider::Right;
    return Collider::Top;
}

void Collider::handle(Collider *other, Collider::Side side) {
    owner->handle_collision(other->owner, side);
}
