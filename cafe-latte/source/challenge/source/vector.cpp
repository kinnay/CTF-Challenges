
#include "vector.h"

Vector::Vector() : Vector(0, 0, 0) {}

Vector::Vector(double x, double y, double z) {
    this->x = x;
    this->y = y;
    this->z = z;
}

Vector Vector::operator +(const Vector &other) {
    return Vector(x + other.x, y + other.y, z + other.z);
}

Vector &Vector::operator +=(const Vector &other) {
    return *this = *this + other;
}
