
#include "common/stringutils.h"
#include "common/exceptions.h"
#include <cctype>


StringFormatter::StringFormatter(const char *msg) {
	this->msg = msg;
	pos = 0;
}

std::string StringFormatter::format() {
	std::string s;
	
	char c = read();
	while (c) {
		if (c == '%') {
			char next = read();
			if (next == '%') {
				s += '%';
			}
			else {
				runtime_error("Not enough arguments for string formatting");
			}
		}
		else {
			s += c;
		}
		c = read();
	}
	return s;
}

char StringFormatter::read() {
	return msg[pos++];
}


bool StringUtils::parseint(std::string str, int *value) {
	size_t pos = 0;
	
	bool sign = false;
	if (str[pos] == '-') {
		sign = true;
		pos++;
	}
	
	if (pos >= str.size()) {
		return false;
	}
	
	*value = 0;
	while (pos < str.size()) {
		if (!isdigit(str[pos])) {
			return false;
		}
		*value = *value * 10 + str[pos] - '0';
		
		if (*value > 99999999) {
			return false;
		}
		
		pos++;
	}
	
	if (sign) {
		*value = -*value;
	}
	return true;
}
