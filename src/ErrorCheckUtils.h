#ifndef WIFISNIFFER_ERRORCHECKUTILS_H
#define WIFISNIFFER_ERRORCHECKUTILS_H

#define CHK(x) do { \
    int retval = (x); \
    if (retval != 0) { \
        std::cerr << "Runtime error: " << #x << " returned " << retval << " at " << __FILE__ << ":" << __LINE__ << std::endl; \
    } \
} while (0)

#endif //WIFISNIFFER_ERRORCHECKUTILS_H
