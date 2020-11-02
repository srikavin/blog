+++
title = "picoCTF 2018 - circuit123"
date = 2018-10-17T02:23:29.709Z
updated = 2018-10-17T02:29:08.242Z
aliases = ["/posts/5bc69d21649fac2c4579918a-picoctf-2018-circuit123"]
[taxonomies]
tags = ['picoctf18', 'python', 'z3', 'reversing']
categories = ["ctf-writeups"]
+++

# Problem
> Can you crack the key to [decrypt](https://2018shell2.picoctf.com/static/27ebc8a7ba2202cfcba1471080e05e2c/decrypt.py) 
>[map2](https://2018shell2.picoctf.com/static/27ebc8a7ba2202cfcba1471080e05e2c/map2.txt) for us? The key to 
>[map1](https://2018shell2.picoctf.com/static/27ebc8a7ba2202cfcba1471080e05e2c/map1.txt) is 11443513758266689915.

## Hint
> z3

# Solution
Given the problem and the hint, it is clear that we can use z3 to solve this problem. We can
create a z3 `BitVec` and pass it into the verify function to avoid writing a custom decrypter. Because we don't know the 
length of the bit vector, I used a conservative estimate of `128`.

<!-- more -->

[Jupyter Notebook](https://mybinder.org/v2/gh/srikavin/ctf-writeups/master?filepath=picoctf2018%2Fcircuit123%2Fmain.ipynb)
