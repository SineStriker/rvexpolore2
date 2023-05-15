#include <sys/syscall.h>
#include <unistd.h>

int num2str(char *buf, int n) {
    int len = 0;
    int num = n;
    while (num > 0) {
        len++;
        num /= 10;
    }
    buf[len] = '\0';

    int res = len;
    num = n;
    while (num > 0) {
        buf[--len] = '0' + num % 10;
        num /= 10;
    }
    return res;
}

ssize_t my_write(int fd, const void *buf, size_t size) {
    ssize_t ret;
    asm volatile("syscall"
                 : "=a"(ret)
                 //                 EDI      RSI       RDX
                 : "0"(__NR_write), "D"(fd), "S"(buf), "d"(size)
                 : "rcx", "r11", "memory");
    return ret;
}

volatile int n = 5;

int main() {
    int t;
    switch (n) {
        case 0:
            t = 48;
            break;
        case 1:
            t = 49;
            break;
        case 2:
            t = 50;
            break;
        case 3:
            t = 51;
            break;
        default:
            break;
    }

    // Convert to string
    char msg[20];
    int len = num2str(msg, t);
    msg[len++] = '\n';

    // write(STDOUT_FILENO, msg, len);
    // syscall(SYS_write, STDOUT_FILENO, msg, len);
    my_write(STDOUT_FILENO, msg, len);

    return 0;
}