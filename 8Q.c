#include <stdio.h>
#include <string.h>

#define N (20 + 5)
int col[N] = {0}, dg[2 * N] = {0}, udg[2 * N] = {0}; // 由于C89标准不存在bool类型，这里使用int代替
char g[N][N];
int n, cnt;

void dfs(int u) {
    if (u == n) {
        for (int i = 0; i < n; i++) {
            for (int j = 0; j < n; j++) {
                // printf("%c", g[i][j]);
            }
            // printf("\n");
        }
        // printf("\n");
        cnt += 1;
        return;
    }

    for (int i = 0; i < n; i++) {
        if (!col[i] && !dg[u - i + n] && !udg[u + i]) {
            g[u][i] = 'Q';
            col[i] = dg[u - i + n] = udg[u + i] = 1;
            dfs(u + 1);
            col[i] = dg[u - i + n] = udg[u + i] = 0;
            g[u][i] = '.';
        }
    }
}

void task_1(void) {
    int num = 100;
    while (num--) {
        memset(col, 0, sizeof(col));
        memset(dg, 0, sizeof(dg));
        memset(udg, 0, sizeof(udg));
        n = 8;
        for (int i = 0; i < n; i++) {
            for (int j = 0; j < n; j++) {
                g[i][j] = '.';
            }
        }
        dfs(0);
    }
    //printf("cnt: %d\n", cnt);
}

int main() {
    cnt = 0;
    task_1();
    return 0;
}
