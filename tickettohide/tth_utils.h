#ifndef OTLS_TTH_UTILS_H
#define OTLS_TTH_UTILS_H

#include <iomanip>
#include <iostream>
#include <string>
#include <charconv>

inline void hex_str_to_bytes(unsigned char* dst, std::string& hex_str) {
    for (size_t i = 0; i < hex_str.size(); i += 2) {
        int val = std::stoi(hex_str.substr(i, 2), nullptr, 16);
        dst[i/2] = static_cast<unsigned char>(val);
    }
}

inline void print_as_hex(const unsigned char* data, size_t len, std::ostream& out = cout) {
    out << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < len; ++i) {
        out << std::setw(2) << static_cast<unsigned>(data[i] & 0xff);
    }
    out << std::endl << std::dec;
}

inline void print_as_hex_reversed(const unsigned char* data, size_t len, std::ostream& out = cout) {
    out << std::hex << std::setfill('0');
    for (std::size_t i = len; i > 0; --i) {
        out << std::setw(2) << static_cast<unsigned>(data[i - 1] & 0xff);
    }
    out << std::endl << std::dec;
}

inline void print_as_hex(const std::string& str, std::ostream& out = cout) {
    print_as_hex((unsigned char*) str.data(), str.size(), out);
}

inline void print_as_hex_reversed(const std::string& str, std::ostream& out = cout) {
    print_as_hex_reversed((unsigned char*) str.data(), str.size(), out);
}

inline void print_bin_str_as_hex(const std::string& bin_str, std::ostream& out = cout) {
    out << std::hex << std::setfill('0');
    for (size_t i = 0; i + 7 < bin_str.size(); i += 8) {
        std::bitset<8> b(bin_str.substr(i, 8));   // take 8 bits
        out << std::setw(2) << b.to_ulong();
    }
    out << std::endl;
}

inline void print_bin_str_as_hex_reversed(const std::string& bin_str, std::ostream& out = cout) {
    string rev_str = bin_str;
    reverse(rev_str.begin(), rev_str.end());
    print_bin_str_as_hex(rev_str, out);
}

#endif // OTLS_TTH_UTILS_H
