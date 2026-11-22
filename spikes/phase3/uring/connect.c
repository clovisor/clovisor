// connect: one IORING_OP_CONNECT to argv[1]:argv[2] (IPv4), with no liburing,
// to show whether io_uring connects pass the cgroup/connect4 hook.
// Prints the CQE result and, on success, the first bytes the peer sends.
#include <arpa/inet.h>
#include <linux/io_uring.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 3) { fprintf(stderr, "usage: connect IP PORT\n"); return 2; }
    struct io_uring_params p; memset(&p, 0, sizeof p);
    int ring = syscall(__NR_io_uring_setup, 4, &p);
    if (ring < 0) { perror("io_uring_setup"); return 1; }
    size_t sqsz = p.sq_off.array + p.sq_entries * sizeof(unsigned);
    size_t cqsz = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);
    char *sq = mmap(0, sqsz, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_POPULATE, ring, IORING_OFF_SQ_RING);
    char *cq = mmap(0, cqsz, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_POPULATE, ring, IORING_OFF_CQ_RING);
    struct io_uring_sqe *sqes = mmap(0, p.sq_entries * sizeof(struct io_uring_sqe), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_POPULATE, ring, IORING_OFF_SQES);
    if (sq == MAP_FAILED || cq == MAP_FAILED || sqes == MAP_FAILED) { perror("mmap"); return 1; }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(atoi(argv[2])) };
    inet_pton(AF_INET, argv[1], &a.sin_addr);

    unsigned tail = *(unsigned *)(sq + p.sq_off.tail);
    unsigned idx = tail & *(unsigned *)(sq + p.sq_off.ring_mask);
    struct io_uring_sqe *e = &sqes[idx]; memset(e, 0, sizeof *e);
    e->opcode = IORING_OP_CONNECT; e->fd = fd; e->addr = (unsigned long)&a; e->off = sizeof a;
    ((unsigned *)(sq + p.sq_off.array))[idx] = idx;
    __atomic_store_n((unsigned *)(sq + p.sq_off.tail), tail + 1, __ATOMIC_RELEASE);
    if (syscall(__NR_io_uring_enter, ring, 1, 1, IORING_ENTER_GETEVENTS, 0, 0) < 0) { perror("io_uring_enter"); return 1; }
    unsigned head = *(unsigned *)(cq + p.cq_off.head);
    struct io_uring_cqe *c = (struct io_uring_cqe *)(cq + p.cq_off.cqes) + (head & *(unsigned *)(cq + p.cq_off.ring_mask));
    printf("io_uring connect: res=%d (%s)\n", c->res, c->res < 0 ? strerror(-c->res) : "ok");
    if (c->res == 0) {
        struct sockaddr_in peer; socklen_t l = sizeof peer; char ip[32];
        getpeername(fd, (struct sockaddr *)&peer, &l);
        printf("getpeername: %s:%d\n", inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof ip), ntohs(peer.sin_port));
    }
    return 0;
}
