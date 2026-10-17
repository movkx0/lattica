/* Public timing metadata only; NVTX is supplied by the installed Nsight SDK.
 * cc -O2 -shared -fPIC -I/usr/lib/nsight-systems/target-linux-x64/nvtx/include \
 *    scripts/linux_profile_clock.c -o target/linux-profile-clock.so -ldl
 */
#include <nvtx3/nvToolsExt.h>
void lattica_profile_mark(const char *label) { nvtxMarkA(label); }
