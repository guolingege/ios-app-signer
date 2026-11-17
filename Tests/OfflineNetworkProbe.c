#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>

// No external endpoint or request: a loopback connect must be refused by policy,
// not merely by the absence of a listener. Executed as a child of the offline app.
int main(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { return errno == EPERM ? 0 : 1; }
    struct sockaddr_in address = {
        .sin_len = sizeof(address), .sin_family = AF_INET,
        .sin_port = htons(9), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)
    };
    int result = connect(fd, (struct sockaddr *)&address, sizeof(address));
    int error = errno;
    close(fd);
    return result == -1 && error == EPERM ? 0 : 1;
}
