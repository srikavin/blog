+++
title = "picoCTF 2018 - be-quick-or-be-dead-3"
date = 2018-10-16T13:53:29.636Z
updated = 2020-12-27
aliases = ["/posts/5bc5ed59649fac2c45799185-picoctf-2018-be-quick-or-be-dead-3"]
[taxonomies]
tags = ['picoctf18', 'binary-exploitation', 'reversing']
categories = ["ctf-writeups"]
+++

# Problem
> As the [song](https://www.youtube.com/watch?v=CTt1vk9nM9c) draws closer to the end, another executable 
>[be-quick-or-be-dead-3](https://2018shell2.picoctf.com/static/1da7d7f7d74df19b7bdb54a3294dd930/be-quick-or-be-dead-3) 
>suddenly pops up. This one requires even faster machines. Can you run it fast enough too?

# Solution
After decompiling the program with [Snowman](https://derevenets.com/), we can see pseudocode for the `calc` function:

```c
uint32_t calc(uint32_t edi) {
    uint32_t eax2;
    uint32_t eax3;
    uint32_t eax4;
    uint32_t eax5;
    uint32_t eax6;
    uint32_t v7;

    if (edi > 4) {
        eax2 = calc(edi - 1);
        eax3 = calc(edi - 2);
        eax4 = calc(edi - 3);
        eax5 = calc(edi - 4);
        eax6 = calc(edi - 5);
        v7 = eax6 * 0x1234 + (eax2 - eax3 + (eax4 - eax5));
    } else {
        v7 = edi * edi + 0x2345;
    }
    return v7;
}
```

<!-- more -->

A way to drastically reduce the runtime of a recursive program is to introduce the dynamic programming concept of 
memoization. It's basically just caching the results of each computation. [Here](https://repl.it/repls/PerfumedBlissfulMouse)
is a memoized version of the function:

```c
#include <stdio.h>
#include <inttypes.h>

uint32_t value[0x18e9f] ;
int exists[0x18e9f];

uint32_t calc(uint32_t edi) {
    //Check if we've already done this calculation
    if(exists[edi]){
    //If we have, just return the precomputed value
      return value[edi];
    }
    //If not, just continue the calculation
    uint32_t eax2;
    uint32_t eax3;
    uint32_t eax4;
    uint32_t eax5;
    uint32_t eax6;
    uint32_t v7;

    if (edi > 4) {
        eax2 = calc(edi - 1);
        eax3 = calc(edi - 2);
        eax4 = calc(edi - 3);
        eax5 = calc(edi - 4);
        eax6 = calc(edi - 5);
        v7 = eax6 * 0x1234 + (eax2 - eax3 + (eax4 - eax5));
    } else {
        v7 = edi * edi + 0x2345;
    }
    //Store the current result into the memo table
    value[edi] = v7;
    exists[edi] = 1;
    return v7;
}

int main(void) {
  printf("%" PRIu32 "\n", calc(0x18e9f));
  return 0;
}
```

Running this program gives: `3610015907`.
Now we need to pass this value to `print_flag`.
We can run the program in gdb.
Using `handle SIGALRM ignore`, we can avoid the termination of the program if we take too long.
Looking at the assembly, we can see that the calculated key is set to `0x6010b0`:
```
(gdb) disassemble get_key
Dump of assembler code for function get_key:
   0x0000000000400815 <+0>:     push   %rbp
   0x0000000000400816 <+1>:     mov    %rsp,%rbp
   0x0000000000400819 <+4>:     mov    $0x400a08,%edi
   0x000000000040081e <+9>:     callq  0x400530 <puts@plt>
   0x0000000000400823 <+14>:    mov    $0x0,%eax
   0x0000000000400828 <+19>:    callq  0x400792 <calculate_key>
   0x000000000040082d <+24>:    mov    %eax,0x20087d(%rip)        # 0x6010b0 <key>
   0x0000000000400833 <+30>:    mov    $0x400a1b,%edi
   0x0000000000400838 <+35>:    callq  0x400530 <puts@plt>
   0x000000000040083d <+40>:    nop
   0x000000000040083e <+41>:    pop    %rbp
   0x000000000040083f <+42>:    retq
End of assembler dump.
```
So, we need to set that address to `3610015907`:

`set {int}0x6010b0=3610015907`.

Now we need to skip the call to `calculate_key.` To do this, we can set a breakpoint right before the call:

`break 0x4008c9`, run the program:

`run`, then when the breakpoint is triggered, jump to the `decrypt_flag` call:
```
(gdb) jump *0x4008d3
Continuing at 0x4008d3.
Printing flag:
picoCTF{dynamic_pr0gramming_ftw_1ffc009d}
[Inferior 1 (process 31) exited normally]
```
