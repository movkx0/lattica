// Exact cubic arithmetic modulo X^3-X-1. No floating point or tensor operations.
inline ulong3 cubic_add(ulong3 a, ulong3 b) { return ulong3(gl_add(a.x,b.x),gl_add(a.y,b.y),gl_add(a.z,b.z)); }
inline ulong3 cubic_neg(ulong3 a) { return ulong3(gl_neg(a.x),gl_neg(a.y),gl_neg(a.z)); }
inline ulong3 cubic_scale(ulong3 a, ulong b) { return ulong3(gl_mul(a.x,b),gl_mul(a.y,b),gl_mul(a.z,b)); }
inline ulong3 cubic_mul(ulong3 a, ulong3 b) {
    ulong t0=gl_mul(a.x,b.x);
    ulong t1=gl_add(gl_mul(a.x,b.y),gl_mul(a.y,b.x));
    ulong t2=gl_add(gl_add(gl_mul(a.x,b.z),gl_mul(a.y,b.y)),gl_mul(a.z,b.x));
    ulong t3=gl_add(gl_mul(a.y,b.z),gl_mul(a.z,b.y));
    ulong t4=gl_mul(a.z,b.z);
    return ulong3(gl_add(t0,t3),gl_add(gl_add(t1,t3),t4),gl_add(t2,t4));
}
kernel void quotient_eval(device const ulong* code [[buffer(0)]],
    device const ulong* rows [[buffer(1)]], device ulong* output [[buffer(2)]],
    constant uint& count [[buffer(3)]], constant uint& stride [[buffer(4)]],
    device ulong* temps [[buffer(5)]], constant uint& rows_count [[buffer(6)]],
    uint row [[thread_position_in_grid]]) {
    ulong3 stack[32]; uint sp=0; ulong3 acc=ulong3(0);
    device const ulong* input=rows+size_t(row)*stride;
    for(uint pc=0;pc<count;pc++) {
        device const ulong* i=code+size_t(pc)*4;
        uint op=uint(i[0]); ulong3 c=ulong3(i[1],i[2],i[3]);
        switch(op) {
            // Typed word planes keep adjacent rows coalesced. Base expressions
            // own one plane; extension expressions own three, without padding.
            case 15: {size_t t=i[1]*rows_count+row;stack[sp++]=i[2]==1?ulong3(temps[t],0,0):ulong3(temps[t],temps[t+rows_count],temps[t+2*rows_count]);break;}
            case 16: {size_t t=i[1]*rows_count+row;ulong3 v=stack[sp-1];temps[t]=v.x;if(i[2]==3){temps[t+rows_count]=v.y;temps[t+2*rows_count]=v.z;}break;}
            case 0: stack[sp++]=c; break;
            case 1: stack[sp++]=ulong3(input[i[1]],0,0); break;
            case 2: stack[sp++]=ulong3(input[i[1]],input[i[1]+1],input[i[1]+2]); break;
            case 3: sp--; stack[sp-1]=ulong3(gl_add(stack[sp-1].x,stack[sp].x),0,0); break;
            case 4: sp--; stack[sp-1]=ulong3(gl_sub(stack[sp-1].x,stack[sp].x),0,0); break;
            case 5: sp--; stack[sp-1]=ulong3(gl_mul(stack[sp-1].x,stack[sp].x),0,0); break;
            case 6: stack[sp-1]=ulong3(gl_neg(stack[sp-1].x),0,0); break;
            case 7: sp--; stack[sp-1]=cubic_add(stack[sp-1],stack[sp]); break;
            case 8: sp--; stack[sp-1]=cubic_add(stack[sp-1],cubic_neg(stack[sp])); break;
            case 9: sp--; stack[sp-1]=cubic_mul(stack[sp-1],stack[sp]); break;
            case 10: stack[sp-1]=cubic_neg(stack[sp-1]); break;
            case 11: acc=cubic_add(acc,cubic_scale(c,stack[--sp].x)); break;
            case 13: sp--; stack[sp-1]=ulong3(gl_sub(stack[sp].x,stack[sp-1].x),0,0); break;
            case 14: sp--; stack[sp-1]=cubic_add(stack[sp],cubic_neg(stack[sp-1])); break;
            case 12: acc=cubic_add(acc,cubic_mul(c,stack[--sp])); break;
        }
    }
    acc=cubic_scale(acc,input[stride-1]);
    output[size_t(row)*3]=gl_canon(acc.x);
    output[size_t(row)*3+1]=gl_canon(acc.y);
    output[size_t(row)*3+2]=gl_canon(acc.z);
}
