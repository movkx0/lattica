#ifdef LATTICA_TUNED_NTT
#ifndef LATTICA_CACHED_ROOT_POWER
#define LATTICA_CACHED_ROOT_POWER 1
// Square powers are already present in the public root table.
inline ulong cached_root_power(__global const ulong *roots, uint order, uint exponent) {
    ulong result = 1UL;
    while (exponent) {
        if (exponent & 1u) result = gl_mul(result, roots[order - 1u]);
        exponent >>= 1;
        --order;
    }
    return result;
}
#endif
#endif
// Shared twiddle and row-scale powers; host admission includes all local storage.
__kernel void ntt_tile_cached(__global const ulong* in, __global ulong* out,
    const uint w, const uint h, const uint s0, const uint lt, const uint log_c,
    const uint fuse_bitrev, const uint log_h, const uint do_canon,
    const uint store_brev, const ulong post_c, const ulong post_b,
    __global const ulong* wlens, __local ulong* tile, __local ulong* powers
#ifdef LATTICA_NTT_TABLES
    , __global const ulong* table
#endif
    ) {
    const uint C=1u<<log_c, lid=get_local_id(0), wg=get_local_size(0);
    const uint tiles=h>>lt, g=(uint)get_group_id(0);
    const uint tidx=g%tiles, cg=g/tiles;
    const uint lo=tidx&((1u<<s0)-1u), hi=tidx>>s0;
    const uint row0=(hi<<(s0+lt))|lo, col0=cg<<log_c;
    const uint rows=1u<<lt, n_el=rows<<log_c, inner=rows>>1;
    for(uint e=lid;e<inner;e+=wg)
#if defined(LATTICA_NTT_TABLES)
        powers[e]=table[e];
#elif defined(LATTICA_TUNED_NTT)
        powers[e]=cached_root_power(wlens,lt,e);
#else
        powers[e]=gl_pow(wlens[lt-1u],(ulong)e);
#endif
    for(uint e=lid;e<lt;e+=wg)
#if defined(LATTICA_NTT_TABLES)
        powers[inner+e]=table[inner+(size_t)lo*lt+e];
#elif defined(LATTICA_TUNED_NTT)
        powers[inner+e]=cached_root_power(wlens,s0+e+1u,lo);
#else
        powers[inner+e]=gl_pow(wlens[s0+e],(ulong)lo);
#endif
    if(post_c!=1UL || post_b!=1UL) {
#ifdef LATTICA_TUNED_NTT
        if(lid==0u) {
            powers[inner+lt]=gl_mul(post_c,gl_pow(post_b,(ulong)row0));
            powers[inner+lt+1u]=gl_pow(post_b,1UL<<s0);
        }
        barrier(CLK_LOCAL_MEM_FENCE);
        const ulong origin=powers[inner+lt], step=powers[inner+lt+1u];
        barrier(CLK_LOCAL_MEM_FENCE);
        for(uint t=lid;t<rows;t+=wg)
            powers[inner+lt+t]=gl_mul(origin,gl_pow(step,(ulong)t));
#else
        for(uint t=lid;t<rows;t+=wg)
            powers[inner+lt+t]=gl_mul(post_c,gl_pow(post_b,(ulong)(row0+(t<<s0))));
#endif
    }
#if defined(LATTICA_NVIDIA_FIELD_CARRY) && defined(LATTICA_SHARED_NTT)
    // Fuse the first butterfly with the global loads. Publish the twiddle
    // first; the existing barrier below publishes the resulting tile. Every
    // workgroup takes the same branch, including the one-stage fallback.
    const uint first_k=lt>1u?2u:1u;
    if(lt>1u) {
        barrier(CLK_LOCAL_MEM_FENCE);
        const ulong tw=powers[inner]; // The first inner-root power is one.
        for(uint b=lid;b<(n_el>>1);b+=wg) {
            const uint t=(b>>log_c)<<1, lc=b&(C-1u), col=col0+lc;
            const uint tl=(t<<log_c)|lc, th=tl+C;
            const uint rl=row0+(t<<s0), rh=rl+(1u<<s0);
            const uint sl=fuse_bitrev?brev(rl,log_h):rl;
            const uint sh=fuse_bitrev?brev(rh,log_h):rh;
            const ulong u=col<w?in[(size_t)sl*w+col]:0UL;
            const ulong v=gl_mul(col<w?in[(size_t)sh*w+col]:0UL,tw);
            tile[tl]=gl_add(u,v);
            tile[th]=gl_sub(u,v);
        }
    } else
#endif
    for(uint e=lid;e<n_el;e+=wg) {
        const uint t=e>>log_c, col=col0+(e&(C-1u));
        const uint r=row0+(t<<s0), sr=fuse_bitrev?brev(r,log_h):r;
        tile[e]=(col<w)?in[(size_t)sr*w+col]:0UL;
    }
    barrier(CLK_LOCAL_MEM_FENCE);
#if defined(LATTICA_NVIDIA_FIELD_CARRY) && defined(LATTICA_SHARED_NTT)
    for(uint k=first_k;k<=lt;k++) {
#else
    for(uint k=1;k<=lt;k++) {
#endif
        const uint hl=1u<<(k-1u);
        const ulong outer=powers[inner+k-1u];
#ifdef LATTICA_SHARED_NTT
        // All columns and repeated row blocks use these same butterfly factors.
        // The host admits this extra half-tile of local words explicitly.
        __local ulong *stage_powers=powers+inner+lt+((post_c!=1UL||post_b!=1UL)?rows:0u);
        for(uint j=lid;j<hl;j+=wg)
            stage_powers[j]=gl_mul(outer,powers[j<<(lt-k)]);
        barrier(CLK_LOCAL_MEM_FENCE);
#endif
        for(uint b=lid;b<(n_el>>1);b+=wg) {
            const uint t2=b>>log_c, lc=b&(C-1u), j=t2&(hl-1u);
            const uint tl=((((t2>>(k-1u))<<k)|j)<<log_c)|lc, th=tl+(hl<<log_c);
#ifdef LATTICA_SHARED_NTT
            const ulong tw=stage_powers[j];
#else
            const ulong tw=gl_mul(outer,powers[j<<(lt-k)]);
#endif
            const ulong u=tile[tl], v=gl_mul(tile[th],tw);
            tile[tl]=gl_add(u,v);
            tile[th]=gl_sub(u,v);
        }
        barrier(CLK_LOCAL_MEM_FENCE);
    }
    for(uint e=lid;e<n_el;e+=wg) {
        const uint t=e>>log_c, col=col0+(e&(C-1u));
        if(col<w) {
            const uint r=row0+(t<<s0), orow=store_brev?brev(r,log_h):r;
            ulong x=tile[e];
            if(post_c!=1UL || post_b!=1UL) x=gl_mul(x,powers[inner+lt+t]);
            out[(size_t)orow*w+col]=do_canon?gl_canon(x):x;
        }
    }
}
