#ifndef OTLS_TTH_UTILS_H
#define OTLS_TTH_UTILS_H

#include <iomanip>
#include <iostream>
#include <string>

inline void print_hex_string(const std::string &byte_string) {
  for (size_t i = 0; i + 7 < byte_string.size(); i += 8) {
    std::bitset<8> b(byte_string.substr(i, 8));   // take 8 bits
    unsigned char c = static_cast<char>(b.to_ulong());
    // print as 2-digit hex
    std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
  }
  std::cout << std::endl;
}

inline void print_hex_string_reversed(std::string byte_string) {
  reverse(byte_string.begin(), byte_string.end());
  print_hex_string(byte_string);
}

#endif // OTLS_TTH_UTILS_H
