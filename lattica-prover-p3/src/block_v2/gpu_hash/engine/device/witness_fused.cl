// One workgroup owns all instructions in each selected wave. Every lane reaches
// every barrier, including inactive lanes and instructions reporting a failure.
// Wide waves stay on the ordinary kernel; no cross-workgroup barrier is used.
__kernel void device_witness_fused(__global const ulong *program,
 uint first, uint count, uint16 ends0, uint16 ends1,
 __global const ulong *input, __global ulong *wires, __global uint *status,
 __global const ulong *rci, __global const ulong *rcp,
 __global const ulong *rcf, __global const ulong *diag) {
 uint lane = get_local_id(0), start = first;
 for (uint wave = 0; wave < count; ++wave) {
   uint end = wave < 16 ? ends0[wave] : ends1[wave-16];
   if (lane < end-start)
     device_witness_instruction(program, start+lane, input, wires, status, rci, rcp, rcf, diag);
   barrier(CLK_GLOBAL_MEM_FENCE);
   start = end;
 }
}
