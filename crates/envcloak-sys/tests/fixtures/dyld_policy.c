/* Independent native test oracle. No EnvCloak or peer-fixture code is linked.
 * Apple dyld calls this SPI with input 0 for a non-encrypted executable without
 * a __RESTRICT segment. The output's bit 1 allows DYLD path variables:
 * https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp
 * https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldDelegates.cpp
 * Query in a clean launch before and after the separate injection launches.
 * An unavailable SPI or failed kernel query fails qualification, never skips.
 */
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

extern int amfi_check_dyld_policy_self(uint64_t input, uint64_t *output);
extern int csr_get_active_config(uint32_t *config);
extern int csops(pid_t pid, unsigned int op, void *buffer, size_t size);

int main(void) {
    uint64_t amfi = 0;
    uint32_t csr = 0, cs = 0;
    int amfi_error = amfi_check_dyld_policy_self(0, &amfi);
    int csr_error = csr_get_active_config(&csr);
    int cs_error = csops(getpid(), 0, &cs, sizeof(cs)); /* CS_OPS_STATUS */
    if (amfi_error || csr_error || cs_error) {
        fprintf(stderr, "policy query failed: amfi=%d csr=%d cs=%d\n",
                amfi_error, csr_error, cs_error);
        return 1;
    }
    /* Reaching main also supplies the post-dyld completion barrier. */
    printf("{\"amfi\":%llu,\"csr\":%u,\"cs\":%u}\n",
           (unsigned long long)amfi, csr, cs);
    return 0;
}
