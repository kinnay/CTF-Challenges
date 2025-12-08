
#pragma once

class Actor;

class Collider {
public:
    enum Side {
        None,
        Left,
        Right,
        Top,
        Bottom
    };

    Collider(Actor *owner, double w, double h);
    Collider(Actor *owner, double x, double y, double w, double h);

    double left();
    double right();
    double top();
    double bottom();

    void move_left(double pos);
    void move_right(double pos);
    void move_top(double pos);
    void move_bottom(double pos);

    bool intersects(Collider *other);

    Side check(Collider *other);
    void handle(Collider *other, Side side);

    Actor *owner;
    bool passive;

    double x, y, w, h;
};
