
#include "math/vector.h"

Vector::Vector() : Vector(0, 0) {}

Vector::Vector(double x, double y) {
    this->x = x;
    this->y = y;
}

Vector Vector::operator +(const Vector &other) {
    return Vector(x + other.x, y + other.y);
}

Vector &Vector::operator +=(const Vector &other) {
    return *this = *this + other;
}
