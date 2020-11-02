+++
title = "nactf 2019 - Dr. J's Group Test Randomizer #2: BBOB"
date = 2019-09-22T17:48:52.836Z
updated = 2019-09-22T22:03:40.121Z
aliases = ["/posts/5d87b40492b65c0964fe369c-nactf-2019-dr-js-group-test-randomizer-2-bbob"]
[taxonomies]
tags = ['nactf2019', 'cryptography', 'z3']
categories = ["ctf-writeups"]
+++

# Challenge

> This is it. The last group test of the year. Dr. J patched his prng again so numbers won't repeat, so I guess 
> Leaf won't get to know the group test pairs ahead of time... oh WEYL. Who knew middle square could make such a good prng?
>
> `nc shell.2019.nactf.com 31382`


We're also given the source of the running application:
```c
#include <stdio.h>
#include <stdint.h>
#include <sodium.h>
#include <stdbool.h>
#include <string.h>
#define NUM_CORRECT 10

uint64_t x = 0, w = 0, s = 0xb5ad4eceda1ce2a9;

uint32_t nextRand() {
  w += s;
  x = x*x + w;
  x = (x>>32) | (x<<32);
  return x % (1UL<<32);
}

void init_seed() {
  uint64_t r1 = (uint64_t) randombytes_random();
  uint64_t r2 = (uint64_t) randombytes_random();
  x = (r1 << 32) + r2;
  r1 = (uint64_t) randombytes_random();
  r2 = (uint64_t) randombytes_random();
  w = (r1 << 32) + r2;
}

void print_flag() {
  FILE *f = fopen("flag.txt", "r");
  char flag[100];
  fgets(flag, sizeof(flag), f);
  printf("%s\n", flag);
  fflush( stdout );
  return;
}

const char *messages[NUM_CORRECT] =
{ "\nHmm... lucky guess...\n",
  "\nWow, that was coincidental!\n",
  "\nWhat? How did you guess that?\n",
  "\nThat's right, but you won't be able to guess right again!\n> ",
  "\nStrangely, that's correct...\n"
};

int main() {
  setvbuf(stdout, NULL, _IONBF, 0);
  init_seed();
  printf("\nWelcome to Dr. J's Random Number Generator v3! We have received reports of "
  "a vulnerability involving repetition of output. This vulnerability has since been patched, "
  "and Dr. J's RNG is now 100%% secure. \n"
  "[r] Print a new random number \n"
  "[g] Guess the next ten random numbers and receive the flag! \n"
  "[q] Quit \n\n");
  char line[100];
  while (true) {
    printf("> ");
    fgets (line, sizeof(line), stdin);
    line[strcspn(line, "\n")] = 0;

    if (!strcmp("r", line)) {
      uint64_t r = nextRand();
      printf("%lu\n", r);
    }
    if (!strcmp("g", line)) {
      printf("\nGuess the next ten random numbers for a flag! "
      "The chance of guessing all ten numbers correctly is 1/(2*10^96). I hope you're lucky! "
      "\nEnter Guess 1:\n> ");

      for (int i = 0; i < NUM_CORRECT; i++) {
        uint64_t guess = 0;
        fgets (line, sizeof(line), stdin);
        sscanf(line, "%lu", &guess);
        if (guess == nextRand()) {
          int m = randombytes_uniform(5);
          printf("%s", messages[m]);
          if (i < NUM_CORRECT-1) {
            printf("Enter Guess %d:\n> ", i+2);
          }
          else {
            printf("What sorcery is this? That's impossible! I guess you deserve this flag:\n");
            print_flag();
            break;
          }
        }
        else {
          printf("That's incorrect. Get out of here!\n");
          break;
        }
      }
      break;
    }
    if (!strcmp("q", line)) {
      printf("\nGoodbye!\n");
      break;
    }
  }
  return 0;
}
```
<!-- more -->

# Solution

This is solvable mathematically as the lower 32 bits of `x` are given after each iteration. However, I chose to use `z3` instead of solving this by hand.

We only need to implement the `nextRand()` function in python because the internal state of the PRNG is only changed here:
```python
so = Solver()

x = BitVec('x', 64)
w = BitVec('w', 64)


def nextRand():
    global x, w

    w += 0xb5ad4eceda1ce2a9

    x = x * x + w
    x = LShR(x, 32) | (x << 32)  # x = b, a
    return Extract(31, 0, URem(x, 1 << 32))
```

An important thing to note with `z3` is the python right shift operator (`>>`) acts as if the bit vector is signed. To treat the bit vector as unsigned, you need to use `LShR`. After implementing this function, we simply need to constrain the output of the function with `z3`:
```python
rand = [
    3482268774,
    3733492975,
    1914513130,
    577823218,
    3863315458,
    820480830,
    4172394928,
    1278770144,
    3099743734,
    3093365285
]

generated = [BitVecVal(x, 32) for x in rand]
for k in generated:
    so.add(nextRand() == k)
```

And finally, we can print out the produced model:

```python
if so.check() == sat:
    print(so.model())
else:
    print('unsat')
```

In testing, I found that this would not return the same initial `x` and `w` values, but the values produced by the PRNG were correct for at least the next 20 values. After we find the values of `x` and `w`, we can use those in the given source in the `init_seed()` function to get the next 10 numbers.


### Full Script
```python

from z3 import *

so = Solver()

x = BitVec('x', 64)
w = BitVec('w', 64)


def nextRand():
    global x, w

    w += 0xb5ad4eceda1ce2a9

    x = x * x + w
    x = LShR(x, 32) | (x << 32)  # x = b, a
    return Extract(31, 0, URem(x, 1 << 32))


rand = [
    3482268774,
    3733492975,
    1914513130,
    577823218,
    3863315458,
    820480830,
    4172394928,
    1278770144,
    3099743734,
    3093365285
]

generated = [BitVecVal(x, 32) for x in rand]

for k in generated:
    so.add(nextRand() == k)

if so.check() == sat:
    print(so.model())
else:
    print('unsat')
```
