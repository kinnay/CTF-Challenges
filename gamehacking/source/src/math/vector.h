
#pragma once

struct Vector {
    Vector();
    Vector(double x, double y);

    Vector operator +(const Vector &other);

    Vector &operator +=(const Vector &other);

    double x, y;
};
