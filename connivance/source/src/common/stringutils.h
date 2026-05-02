
#pragma once

#include "common/typeutils.h"

#include <cstdint>
#include <cstdio>
#include <ios>
#include <stdexcept>
#include <sstream>
#include <string>
#include <type_traits>


class StringFormatter {
public:
	StringFormatter(const char *msg);
	
	std::string format();
	
	template <class T, class... Args>
	std::string format(T param, Args... args) {
		std::string s;
		
		while (true) {
			char c = read();
			
			if (!c) {
				throw std::runtime_error("Not all arguments used during string formatting");
			}
			
			if (c == '%') {
				char next = read();
				if (next == '%') {
					s += '%';
				}
				else {
					bool zero = false;
					size_t width = 0;
					
					if (next == '0') {
						zero = true;
						next = read();
					}
					
					while (isdigit(next)) {
						if (width > 999) {
							throw std::runtime_error("Malformed format specifier");
						}
						width = width * 10 + next - '0';
						next = read();
					}
					
					std::string fmt = format_param(next, param);
					if (fmt.size() < width) {
						fmt = std::string(width - fmt.size(), zero ? '0' : ' ') + fmt;
					}
					return s + fmt + format(args...);
				}
			}
			else {
				s += c;
			}
		}
	}

private:
	char read();
	
	template <class T>
	std::string format_param(char type, T param) {
		switch (type) {
			case 'c': return format_char(param);
			case 's': return format_string(param);
			case 'f': return format_float(param);
			case 'i': return format_number(param);
			case 'x': return format_number(param, true);
			case 'X': return format_number(param, true, true);
			case 'p': return format_ptr(param);
			default:
				throw std::runtime_error("Invalid format specifier");
		}
	}
	
	template <class T>
	std::string format_char(T value) requires Convertible(T, char) {
		return std::string(1, value);
	}
	
	template <class T>
	std::string format_string(T value) requires Convertible(T, std::string) {
		return value;
	}
	
	template <class T>
	std::string format_float(T value) requires Convertible(T, double) {
		return std::to_string((double)value);
	}
	
	template <class T>
	std::string format_number(T value, bool hex = false, bool upper = false) requires (Convertible(T, uint64_t) or IsEnum(T)) {
		std::ostringstream s;
		if (hex) {
			s << std::hex;
		}
		if (upper) {
			s << std::uppercase;
		}
		s << (uint64_t)value;
		return s.str();
	}
	
	template <class T>
	std::string format_ptr(T value) requires Convertible(T, void *) {
		return "0x" + format_number((uint64_t)value, true);
	}
	
	template <class T>
	std::string format_char(T value) requires (not Convertible(T, char)) {
		throw std::runtime_error("Expected a character");
	}
	
	template <class T>
	std::string format_string(T value) requires (not Convertible(T, std::string)) {
		throw std::runtime_error("Expected a string");
	}
	
	template <class T>
	std::string format_float(T value) requires (not Convertible(T, double)) {
		throw std::runtime_error("Expected a float");
	}
	
	template <class T>
	std::string format_number(T value, bool hex = false, bool upper = false) requires (not (Convertible(T, uint64_t) or IsEnum(T))) {
		throw std::runtime_error("Expected an integer");
	}
	
	template <class T>
	std::string format_ptr(T value) requires (not Convertible(T, void *)) {
		throw std::runtime_error("Expected a pointer");
	}
	
	const char *msg;
	size_t pos;
};


class StringUtils {
public:
	static bool parseint(std::string str, int *value);

	template <class... Args>
	static std::string format(const char *msg, Args... args) {
		StringFormatter formatter(msg);
		return formatter.format(args...);
	}
};
