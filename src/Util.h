#ifndef WIFISNIFFER_UTIL_H
#define WIFISNIFFER_UTIL_H

#include <string>
#include <iomanip>

//#define CRC32_POLYNOMIAL 0x82f63b78 // Normal order
#define CRC32_POLYNOMIAL 0xedb88320 // CRC-32 (Ethernet, ZIP, etc.) polynomial in reversed bit order.

uint32_t crc32(uint32_t crc, const unsigned char* buffer, size_t length) {
    int k;
    crc = ~crc;
    while (length--) {
        crc ^= *buffer++;
        for (k = 0; k < 8; k++)
            crc = crc & 1 ? (crc >> 1) ^ CRC32_POLYNOMIAL : crc >> 1;
    }
    return ~crc;
}

uint32_t crc32(const unsigned char* buffer, size_t length) {
    return crc32(0, buffer, length);
}

/** Extracts specified bits counting from right **/
template<typename T>
T extractBits(T number, unsigned left, unsigned right) {
    unsigned r = 0;
    for (unsigned i = left; i <= right; i++) {
        r |= 1 << i;
    }
    return (T) (number & r);
}

template <typename T>
T extractBits(T number, unsigned at) {
    return extractBits(number, at, at);
}

template <typename T>
std::string toString(T item) {
    if constexpr (std::is_same<T, std::string>::value) {
        return item;
    } else {
        return std::to_string(item);
    }
}

template <typename Container>
inline std::string printContainer(const Container& container) {
    if (container.empty()) {
        return "{}";
    }
    std::string result = "{" + toString(*(container.begin()));
    if (container.size() == 1) {
        return result + "}";
    }
    for (auto it = std::next(container.begin()); it != container.end(); ++it) {
        result += ", " + toString(*it);
    }
    result += '}';
    return result;
}

template<class Container, class T>
auto contains(const Container& container, const T& x) -> decltype(container.find(x) != container.end()) {
    return container.find(x) != container.end();
}

inline void hash_combine(std::size_t& seed) { }

template <typename T, typename... Rest>
inline void hash_combine(std::size_t& seed, const T& v, Rest... rest) {
    std::hash<T> hasher;
    seed ^= hasher(v) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
    hash_combine(seed, rest...);
}

#endif //WIFISNIFFER_UTIL_H
