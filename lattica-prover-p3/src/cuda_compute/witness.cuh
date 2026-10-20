// Native adapters for the shared recursive execution kernels.
// The field, lookup and wallet adapters supply integer arithmetic helpers,
// including wallet.cuh's perm8 for separately owned Poseidon2 constants.
// Keep one definition in the combined wallet/witness compilation unit.
#define LATTICA_WITNESS_FN __device__ __forceinline__
