#pragma once

#include <sys/syscall.h>
#include <unistd.h>


//=================================================================
// Syscalls
//=================================================================
ssize_t my_read(int fd, void *buf, size_t size);

ssize_t my_write(int fd, const void *buf, size_t size);

void my_exit(int code);



//=================================================================
// Utils
//=================================================================
#pragma GCC push_options
#pragma GCC optimize("O0")
int num2str(char *buf, int n) {
    int len = 0;

    int res = 0;
    if (n < 0) {
        n = -n;
        buf[len++] = '-';
    }

    int num = n;
    while (num > 0) {
        len++;
        num /= 10;
    }
    buf[len] = '\0';

    res = len;
    num = n;
    while (num > 0) {
        buf[--len] = '0' + num % 10;
        num /= 10;
    }

    return res;
}

void print_num(int n) {
    // Convert to string
    char msg[sizeof(n) + 2];
    int len = num2str(msg, n);
    msg[len++] = '\n';

    // print
    my_write(STDOUT_FILENO, msg, len);
}

void print_str(char *s) {
    size_t i = 0;
    while (s[i]) {
        ++i;
    }
    my_write(STDOUT_FILENO, s, i);
}

int read_num() {
    int res = 0;
    char ch;
    while (my_read(STDIN_FILENO, &ch, sizeof(ch))) {
        if (ch == '\n' || ch == ' ')
            break;
        res = res * 10 + (ch - '0');
    }
    return res;
}

#pragma GCC pop_options


//=================================================================
// Syscall implementation
//=================================================================

ssize_t my_read(int fd, void *buf, size_t size) {
    ssize_t ret;
    asm volatile("syscall"
                 : "=a"(ret)
                 //                 EDI      RSI       RDX
                 : "0"(__NR_read), "D"(fd), "S"(buf), "d"(size)
                 //  : "rcx", "r11", "memory"
    );
    return ret;
}

ssize_t my_write(int fd, const void *buf, size_t size) {
    ssize_t ret;
    asm volatile("syscall"
                 : "=a"(ret)
                 //                 EDI      RSI       RDX
                 : "0"(__NR_write), "D"(fd), "S"(buf), "d"(size)
                 //  : "rcx", "r11", "memory"
    );
    return ret;
}

void my_exit(int code) {
    int ret;
    asm volatile("syscall"
                 : "=a"(ret)
                 //                 EDI
                 : "0"(__NR_exit), "D"(code));
}