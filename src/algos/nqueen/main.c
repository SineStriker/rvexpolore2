#include <sys/syscall.h>
#include <unistd.h>

#define N 8 // N代表皇后个数

int queen[N + 1]; // 表示皇后所在的位置，如queen[1]=2表示皇后在第一行第二列
int count = 0;

inline int abs(int n) {
    return n >= 0 ? n : (-n);
}

int isQueen(int j) { // 判断该列能否放置皇后，能放返回1，不能返回0
    int i;
    for (i = 1; i < j; i++) { // 检查已经摆放好的皇后是否在同一列上或者在同一斜线上
        if (queen[i] == queen[j] || abs(queen[i] - queen[j]) == j - i) {
            return 0;
        }
    }
    return 1;
}

/**
 * @brief
 *
 * @param j 行数，递归时用到
 * i为列数
 */
void Nqueen(int j) {
    int i;
    for (i = 1; i <= N; i++) // 遍历行,即遍历所有方案，找出可行方案
    {
        queen[j] = i;
        if (isQueen(j)) { // 判断该列能否放置皇后
            if (j == N) { // 所有皇后拜访好了，输出摆放方案
                count++;
            } else {
                Nqueen(j + 1); // 递归，摆放下一个皇后
            }
        }
    }
}

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

int main() {
    Nqueen(1);

    // Convert to string
    char msg[20];
    int len = num2str(msg, count);
    msg[len++] = '\n';

    // write(STDOUT_FILENO, msg, len);
    // syscall(SYS_write, STDOUT_FILENO, msg, len);
    my_write(STDOUT_FILENO, msg, len);

    return 0;
}