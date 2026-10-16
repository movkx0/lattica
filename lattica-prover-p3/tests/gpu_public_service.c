/* Independently linked service child for native public protocol qualification. */
#define _GNU_SOURCE
#include "lattica_prover_p3.h"
#include <alloca.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <malloc.h>

static volatile unsigned char stack_sink;

/* Test-host-only pressure; the production Rust library never sets mallopt. */
static int retain_allocator_capacity(void) {
    typedef struct mallinfo2 (*read_info_fn)(void);
    read_info_fn read_info = (read_info_fn)dlsym(RTLD_DEFAULT, "mallinfo2");
    if (!read_info || !mallopt(M_MMAP_THRESHOLD, 1024 * 1024 * 1024) ||
        !mallopt(M_TRIM_THRESHOLD, -1)) return 0;
    size_t count = 768ul << 20;
    volatile unsigned char *bytes = malloc(count);
    if (!bytes) return 0;
    for (size_t index = 0; index < count; index += 4096)
        bytes[index] = (unsigned char)(index / 4096);
    struct mallinfo2 held = read_info();
    free((void *)bytes);
    struct mallinfo2 freed = read_info();
    printf("native_retained_heap_fixture requested_bytes=%zu held_arena_bytes=%zu "
           "freed_arena_bytes=%zu freed_capacity_bytes=%zu mapped_bytes=%zu\n",
           count, held.arena, freed.arena, freed.fordblks, freed.hblkhd);
    fflush(stdout);
    return held.arena >= count && freed.arena >= count &&
           freed.fordblks >= count && freed.hblkhd == 0;
}

/* Qualification-only link wrapper. The pinned Rust UnixStream implementation
 * sends the READY kind (2) as one byte before its length/body. Inject after
 * startup admission, on that same service thread, without changing wire bytes
 * or adding an unreserved fixture thread. Other sends pass through unchanged.
 * Compile with -DLATTICA_TEST_WRAP_SEND -Wl,--wrap=send for this mode. */
#ifdef LATTICA_TEST_WRAP_SEND
static struct stat service_socket;
static _Thread_local int inject_on_ready;
ssize_t __real_send(int fd, const void *buffer, size_t count, int flags);
ssize_t __wrap_send(int fd, const void *buffer, size_t count, int flags) {
    if (inject_on_ready && count == 1 && *(const unsigned char *)buffer == 2) {
        struct stat current;
        if (!fstat(fd, &current) && S_ISSOCK(current.st_mode) &&
            current.st_dev == service_socket.st_dev &&
            current.st_ino == service_socket.st_ino) {
            inject_on_ready = 0;
            if (!retain_allocator_capacity()) _exit(98);
            puts("native_retained_heap_injected boundary=ready_header wrapped_send=true");
            fflush(stdout);
        }
    }
    return __real_send(fd, buffer, count, flags);
}
#endif

/* Returning releases the frame, but Linux retains the grown main mapping. */
__attribute__((noinline)) static void retain_stack_mapping(size_t count) {
    volatile unsigned char *bytes = alloca(count);
    for (size_t index = 0; index < count; index += 4096) bytes[index] = 1;
    stack_sink = bytes[count - 4096];
}

int main(int argc, char **argv) {
    if (argc != 3) return 90;
    int retained_stack = strcmp(argv[2], "retained-stack") == 0;
    int unlimited_stack = strcmp(argv[2], "unlimited-stack") == 0;
    int cold_heap = strcmp(argv[2], "retained-heap-before-start") == 0;
    int cold_private = strcmp(argv[2], "private-mapping-before-start") == 0;
    void *private_mapping = MAP_FAILED;
    if (cold_private) {
        private_mapping = mmap(NULL, 513ul << 20, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (private_mapping == MAP_FAILED) return 99;
        *(volatile unsigned char *)private_mapping = 1;
        puts("native_private_mapping_fixture mapped_bytes=537919488 writable=true shared=false");
        fflush(stdout);
    }
    if (cold_heap && !retain_allocator_capacity()) return 97;
    if (strcmp(argv[2], "retained-heap") == 0) {
#ifdef LATTICA_TEST_WRAP_SEND
        if (fstat(STDIN_FILENO, &service_socket) || !S_ISSOCK(service_socket.st_mode)) return 98;
        inject_on_ready = 1;
#else
        fputs("retained-heap requires the qualification send wrapper\n", stderr);
        return 98;
#endif
    }
    if (retained_stack || unlimited_stack) {
        struct rlimit limit;
        if (getrlimit(RLIMIT_STACK, &limit)) return 94;
        limit.rlim_cur = unlimited_stack ? RLIM_INFINITY : 32ul << 20;
        if (setrlimit(RLIMIT_STACK, &limit)) return 95;
        if (retained_stack) {
            retain_stack_mapping(12ul << 20);
            limit.rlim_cur = 8ul << 20;
            if (setrlimit(RLIMIT_STACK, &limit)) return 96;
        }
    }
    unsigned char bootstrap[65537];
    FILE *file = fopen(argv[1], "rb");
    if (!file) return 91;
    size_t size = fread(bootstrap, 1, sizeof bootstrap, file);
    int read_error = ferror(file);
    fclose(file);
    if (read_error || size == 0 || size > 65536) return 92;
    uint64_t completed = UINT64_MAX;
    int32_t rc = lattica_gpu_public_worker_serve(STDIN_FILENO, bootstrap, size, &completed);
    int descriptor_preserved = fcntl(STDIN_FILENO, F_GETFD) >= 0;
    int retired = lattica_gpu_drain() == 1;
    int shutdown_ok = lattica_gpu_shutdown() == 0;
    struct rlimit data_limit;
    if (getrlimit(RLIMIT_DATA, &data_limit)) return 100;
    printf("native_private_data_limit soft_bytes=%ju hard_bytes=%ju\n",
           (uintmax_t)data_limit.rlim_cur, (uintmax_t)data_limit.rlim_max);
    if (cold_private && munmap(private_mapping, 513ul << 20)) return 101;
    printf("native_public_service_result rc=%d completed=%" PRIu64
           " descriptor_preserved=%d gpu_retired=%d shutdown_ok=%d\n",
           rc, completed, descriptor_preserved, retired, shutdown_ok);
    int expected = strcmp(argv[2], "reject") == 0 || retained_stack || unlimited_stack || cold_heap || cold_private;
    return rc == expected && (rc == 0 || completed == 0) &&
           descriptor_preserved && retired && shutdown_ok ? 0 : 93;
}
