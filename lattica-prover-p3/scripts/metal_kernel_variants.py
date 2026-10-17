"""Deterministic, exact Metal variants of the reviewed shared kernels."""
import re


def variants(source):
    # The width-eight Goldilocks diagonal is fixed by the protocol. Normalize
    # before halving so this also accepts the redundant representatives used
    # internally by gl_add/gl_mul. The addition cannot overflow a u64.
    helpers = '''
inline ulong gl_half(ulong x) {
    ulong c=gl_canon(x);
    return (c>>1) + ((c&1UL) ? 0x7fffffff80000001UL : 0UL);
}
inline ulong gl_diag8(ulong x, uint lane) {
    switch(lane) {
        case 0: return gl_neg(gl_add(x,x));
        case 1: return x;
        case 2: return gl_add(x,x);
        case 3: return gl_half(x);
        case 4: return gl_add(gl_add(x,x),x);
        case 5: return gl_neg(gl_half(x));
        case 6: return gl_neg(gl_add(gl_add(x,x),x));
        default: { ulong twice=gl_add(x,x); return gl_neg(gl_add(twice,twice)); }
    }
}
inline ulong gl_diagonal(ulong x, device const ulong* diag, uint lane) {
#if LATTICA_SPECIALIZED_DIAGONAL
    return gl_diag8(x,lane);
#else
    return gl_mul(x,diag[lane]);
#endif
}
'''
    reference = 'inline ulong gl_mul(ulong a,ulong b){ return gl_reduce128(a*b, metal_mul_hi(a,b)); }'
    assert reference in source
    source = source.replace(reference, '''#if LATTICA_OPTIMIZED
inline ulong gl_mul(ulong a,ulong b) {
    ulong p0=ulong(uint(a))*uint(b), p1=ulong(uint(a))*uint(b>>32);
    ulong p2=ulong(uint(a>>32))*uint(b), p3=ulong(uint(a>>32))*uint(b>>32);
    ulong carry=(p0>>32)+ulong(uint(p1))+ulong(uint(p2));
    ulong lo=ulong(uint(p0)) | (carry<<32);
    ulong hi=p3+(p1>>32)+(p2>>32)+(carry>>32);
    return gl_reduce128(lo,hi);
}
#else
''' + reference + '\n#endif')
    ntt = source[source.index('kernel void ntt_tile('):source.index('// ---- Poseidon2')]
    cached = ntt.replace('ntt_tile(', 'ntt_tile_cached(').replace(
        'threadgroup ulong* tile [[threadgroup(0)]],',
        'device const ulong* tables [[buffer(14)]],\n    threadgroup ulong* tile [[threadgroup(0)]],')
    cached = cached.replace('ulong outer=gl_pow(wlens[s0+k-1u],(ulong)lo);', '')
    cached = cached.replace('gl_mul(outer,gl_pow(wlens[k-1u],(ulong)j))',
                            'tables[(1u<<(s0+k-1u))-1u+lo+(j<<s0)]')
    cached = cached.replace('gl_mul(post_c,gl_pow(post_b,(ulong)r))', 'tables[h-1u+r]')
    source = source.replace('// ---- Poseidon2', cached + '''
kernel void ntt_tables(device const ulong* roots [[buffer(0)]],
    device ulong* table [[buffer(1)]], constant uint& h [[buffer(2)]],
    constant ulong& c [[buffer(3)]], constant ulong& b [[buffer(4)]],
    uint i [[thread_position_in_grid]]) {
    if(i>=h) return;
    if(i<h-1u) { uint stage=31u-clz(i+1u); uint j=i-((1u<<stage)-1u);
        table[i]=gl_pow(roots[stage],j); }
    table[h-1u+i]=gl_mul(c,gl_pow(b,i));
}
// ---- Poseidon2''', 1)
    source = source.replace('// ---- Poseidon2', helpers + '\n// ---- Poseidon2', 1)
    source = source.replace('gl_mul(s[i],diag[i])', 'gl_diagonal(s[i],diag,uint(i))')
    start = source.index('inline void perm8(')
    end = source.index('// leaf hash', start)
    original = source[start:end]
    out = ['inline void perm8(thread ulong* s,device const ulong* rci,device const ulong* rcp,device const ulong* rcf,device const ulong* diag){']
    out.extend(f'ulong x{i}=s[{i}];' for i in range(8))
    def external():
        out.append('{')
        for offset in (0, 4):
            a,b,c,d = [f'x{i+offset}' for i in range(4)]
            out.extend(['{',f'ulong t01=gl_add({a},{b}),t23=gl_add({c},{d});',
                'ulong t0123=gl_add(t01,t23);',f'ulong t01123=gl_add(t0123,{b}),t01233=gl_add(t0123,{d});',
                f'{d}=gl_add(t01233,gl_add({a},{a}));',f'{b}=gl_add(t01123,gl_add({c},{c}));',
                f'{a}=gl_add(t01123,t01);',f'{c}=gl_add(t01233,t23);','}'])
        out.extend(f'ulong z{i}=gl_add(x{i},x{i+4});' for i in range(4))
        out.extend(f'x{i}=gl_add(x{i},z{i%4});' for i in range(8))
        out.append('}')
    external()
    for r in range(4):
        out.extend(f'x{i}=gl_pow7(gl_add(x{i},rci[{r*8+i}]));' for i in range(8))
        external()
    for r in range(22):
        out.extend(['{',f'x0=gl_pow7(gl_add(x0,rcp[{r}]));', 'ulong sum=0UL;'])
        out.extend(f'sum=gl_add(sum,x{i});' for i in range(8))
        out.extend(f'x{i}=gl_add(gl_diagonal(x{i},diag,{i}u),sum);' for i in range(8))
        out.append('}')
    for r in range(4):
        out.extend(f'x{i}=gl_pow7(gl_add(x{i},rcf[{r*8+i}]));' for i in range(8))
        external()
    out.extend(f's[{i}]=x{i};' for i in range(8))
    out.append('}')
    source = source[:start] + '#if LATTICA_OPTIMIZED\n' + '\n'.join(out) + '\n#else\n' + original + '#endif\n' + source[end:]
    # Only the final NTT stage writes prefixes. Every output row/column has one
    # owner, including when bit-reversed stores cross threadgroup row ranges.
    for kernel, first_arg in ((ntt, 14), (cached, 15)):
        name = 'ntt_tile_cached' if first_arg == 15 else 'ntt_tile'
        prefix = kernel.replace(f'kernel void {name}(', f'kernel void {name}_prefix(')
        args = [f'device ulong* prefix [[buffer({first_arg})]],',
                f'constant uint& prefix_width [[buffer({first_arg+1})]],',
                f'constant uint& prefix_first [[buffer({first_arg+2})]],',
                f'constant uint& prefix_height [[buffer({first_arg+3})]],']
        prefix = prefix.replace('threadgroup ulong* tile [[threadgroup(0)]],',
                                '\n    '.join(args) + '\n    threadgroup ulong* tile [[threadgroup(0)]],')
        store = 'out[(size_t)orow*w+col]=do_canon?gl_canon(x):x;'
        assert prefix.count(store) == 1
        prefix = prefix.replace(store, store + '''
      if(orow<prefix_height)
        prefix[(size_t)orow*prefix_width+prefix_first+col]=gl_canon(x);''')
        source += prefix
    source += """
kernel void diagonal_probe(device const ulong* input [[buffer(0)]], device ulong* output [[buffer(1)]],
    uint i [[thread_position_in_grid]]) {
    for(uint lane=0;lane<8;lane++) output[(size_t)i*8+lane]=gl_canon(gl_diag8(input[i],lane));
}
kernel void prefix_scatter(device const ulong* src [[buffer(0)]], device ulong* dst [[buffer(1)]],
    constant uint& width [[buffer(2)]], constant uint& first [[buffer(3)]],
    constant uint& cols [[buffer(4)]], uint i [[thread_position_in_grid]]) {
    dst[(i/cols)*width+first+i%cols]=gl_canon(src[i]);
}
"""
    return "\n".join(line.rstrip() for line in source.splitlines()) + "\n"
