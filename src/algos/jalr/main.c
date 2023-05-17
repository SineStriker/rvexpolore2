#include "my_syscall.h"

int main() {
    int t = -1;

    int n = read_num();

    switch (n) {
        case 0:
            print_str("00\n");
            break;
        case 1:
            t = 679;
            break;
        case 2:
            t = -4;
            break;
        case 3:
            print_str("03\n");
            print_str("04\n");
            print_str("05\n");
            print_str("06\n");
            break;
        case 4:
            t = 8;
            break;
        case 5:
            t = 4;
            break;
        default:
            break;
    }

    print_num(t);

    return 0;
}