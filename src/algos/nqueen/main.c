#include "my_syscall.h"

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

int main() {
    Nqueen(1);

    // print
    print_num(count);

    // exit
    my_exit(0);

    return 0;
}