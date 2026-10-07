/* Native peers for M3-07. Only synthetic frames, in isolated test homes. */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static void transfer(int fd, void *p, size_t n, int writing) {
    while (n) {
        ssize_t got = writing ? write(fd, p, n) : read(fd, p, n);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) exit(3);
        p = (char *)p + got;
        n -= (size_t)got;
    }
}

static void request(int fd) {
    /* Parent supplies a complete bounded frame. Reply is copied to stdout. */
    unsigned char buf[8192];
    unsigned int len;
    transfer(0, &len, 4, 0);
    size_t n = ntohl(len);
    if (n > sizeof(buf)) exit(4);
    transfer(0, buf, n, 0);
    transfer(fd, &len, 4, 1);
    transfer(fd, buf, n, 1);
    ssize_t got = read(fd, &len, 4);
    if (!got || (got < 0 && errno == ECONNRESET)) {
        transfer(1, "CLOSED\n", 7, 1);
        return;
    }
    if (got != 4 || ntohl(len) > sizeof(buf)) exit(5);
    n = ntohl(len);
    transfer(fd, buf, n, 0);
    transfer(1, &len, 4, 1);
    transfer(1, buf, n, 1);
}

int main(int argc, char **argv) {
    if (argc < 3) return 2;
    if ((!strcmp(argv[1], "parent") || !strcmp(argv[1], "chain")) && argc != 4) return 2;
    if (!strcmp(argv[1], "parent") || (!strcmp(argv[1], "chain") && atoi(argv[3]) > 0)) {
        if (argc != 4) return 9;
        pid_t child = fork();
        if (child < 0) return 10;
        if (child == 0) {
            if (!strcmp(argv[1], "parent")) {
                execl(argv[3], argv[3], "call", argv[2], NULL);
            } else {
                char count[24];
                snprintf(count, sizeof(count), "%d", atoi(argv[3]) - 1);
                execl(argv[0], argv[0], "chain", argv[2], count, NULL);
            }
            _exit(13);
        }
        int status;
        pid_t got;
        do { got = waitpid(child, &status, 0); } while (got < 0 && errno == EINTR);
        return got == child && WIFEXITED(status) ? WEXITSTATUS(status) : 11;
    }
    if (!strcmp(argv[1], "inherited")) {
        request(atoi(argv[2]));
        return 0;
    }
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return 3;
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    if (strlen(argv[2]) >= sizeof(addr.sun_path)) return 4;
    strcpy(addr.sun_path, argv[2]);
    if (!strcmp(argv[1], "listen")) {
        if (bind(fd, (void *)&addr, sizeof(addr)) || listen(fd, 1)) return 5;
        transfer(1, "READY\n", 6, 1);
        int conn = accept(fd, NULL, NULL);
        if (conn < 0) return 6;
        char buf[8192];
        ssize_t n = read(conn, buf, sizeof(buf));
        if (n < 0) return 7;
        printf("%zd\n", n);
        return 0;
    }
    if (connect(fd, (void *)&addr, sizeof(addr))) return 8;
    request(fd); /* A response is the barrier: daemon accepted this exact process. */
    if (!strcmp(argv[1], "exec") || !strcmp(argv[1], "pass") || !strcmp(argv[1], "reconnect")) {
        if (argc != 4) return 9;
        if (!strcmp(argv[1], "reconnect")) {
            close(fd);
            execl(argv[3], argv[3], "call", argv[2], NULL);
            return 13;
        }
        char number[24];
        snprintf(number, sizeof(number), "%d", fd);
        if (!strcmp(argv[1], "pass")) {
            pid_t child = fork();
            if (child < 0) return 10;
            if (child > 0) {
                close(fd);
                int status;
                if (waitpid(child, &status, 0) != child) return 11;
                return WIFEXITED(status) ? WEXITSTATUS(status) : 12;
            }
        }
        execl(argv[3], argv[3], "inherited", number, NULL);
        return 13;
    }
    /* Keep this process alive until the controller releases it. */
    char end;
    (void)read(0, &end, 1);
    return 0;
}
