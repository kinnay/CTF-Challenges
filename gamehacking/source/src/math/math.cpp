
#include "math/math.h"

#include <cmath>

double move_value_to(double value, double target, double step) {
	double diff = fabs(target - value);
	if (diff < step) {
		return target;
	}
	if (target < value) {
		return value - step;
	}
	return value + step;
}
