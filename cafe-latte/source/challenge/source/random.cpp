
#include "random.h"

#include <cstdlib>

int random_int(int min, int max) {
    return min + rand() % (max - min + 1);
}

double random_double(double min, double max) {
    double scale = rand() / (double)RAND_MAX;
    return min + scale * (max - min);
}
