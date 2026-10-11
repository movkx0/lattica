/* Independently linked service child for native public protocol qualification. */
#include "lattica_prover_p3.h"
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 3) return 90;
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
    printf("native_public_service_result rc=%d completed=%" PRIu64
           " descriptor_preserved=%d gpu_retired=%d shutdown_ok=%d\n",
           rc, completed, descriptor_preserved, retired, shutdown_ok);
    int expected = strcmp(argv[2], "reject") == 0 ? 1 : 0;
    return rc == expected && (rc == 0 || completed == 0) &&
           descriptor_preserved && retired && shutdown_ok ? 0 : 93;
}
