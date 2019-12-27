# Cyber Challenge 0x02
This challenege is a fair mix between reversing and general Linux knowledge.

## Understanding the task
Before we get to solving this task, let's read the instructions to see what is expected of us:
```text
  The Goal:
  1) The following program receives a secret key. 
  2) Write a crack for the program that computes the secret key ( you can use any coding
  language you prefer: python. Rust. c/c++, java, ...)
  Patching the program to accept Any Key won’t be accepted as a solution!
  Instructions:
  1) Run on linux 64bit machine (Debian/Ubuntu).
  2) IDA may come in handy here (So, read an introduction tutorial to get started).
  3) The program is “heavy” so it will take a few seconds to compute the key.
  The best thing is to wait a few seconds between executions.
  Bonus Question:
  Why does it take some time in order to compute the key when running the program over and over?
  Write the full reason for this behaviour.
```
So, this program has a *secret key* that we need to match.

It is fair to assume that the program will take input from us the user, and then compare the input to its key.
It is also explicitly stated that just patching the program to accept any key is not considered a solution,
and we'll see why that's the case later on.

For convenience, most of the solutions that I'll be showing here will be written in Python (specifically Python 3), although
they can probably be written in most other languages.

## Analyzing the binary
Let's start by looking at the output of running this program.
We are greeted by the following, somewhat barren interface:
```
Please, enter the key:
```
After giving it a very special key, "AAAAAAAA", we get:
```
Please, enter the key:
AAAAAAAA
Please try again
```
This is more or less what we expected.


Before we can get to solving this task, we first need to understand what it is exactly that we are solving.
To do that, let's fire up the trusty Ghidra, gracefully provided by the NSA.

Upon analyzing the binary, Ghidra finds a list of functions that may or may not prove interesting. We can then go one by one inspecting these functions, to try and find something interesting. After a bit of investigation, we find a few noteworthy functions, which Ghidra thankfully tries to decompile for us.

FUN_00100d10:
```c
undefined8 FUN_00100d10(void **param_1)

{
  void *__ptr;
  FILE *__stream;
  size_t sVar1;
  undefined8 uVar2;
  
  __ptr = malloc(10);
  __stream = fopen("/dev/random","rb");
  if (__stream != (FILE *)0x0) {
    uVar2 = 6;
    sVar1 = fread(__ptr,1,10,__stream);
    if (sVar1 == 10) {
      *param_1 = __ptr;
      uVar2 = 0;
    }
    fclose(__stream);
    return uVar2;
  }
  return 5;
}
```

_INIT_1:
```c
void _INIT_1(void)

{
  uint uVar1;
  FILE *__stream;
  char *pcVar2;
  long lVar3;
  undefined8 *puVar4;
  long in_FS_OFFSET;
  undefined4 local_12f;
  undefined2 local_12b;
  undefined local_129;
  undefined8 local_128;
  long local_20;
  
  lVar3 = 0x1f;
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  local_12b = 0;
  local_12f = 0;
  local_129 = 0;
  puVar4 = &local_128;
  while (lVar3 != 0) {
    lVar3 = lVar3 + -1;
    *puVar4 = 0;
    puVar4 = puVar4 + 1;
  }
  *(undefined4 *)puVar4 = 0;
  *(undefined2 *)((long)puVar4 + 4) = 0;
  *(undefined *)((long)puVar4 + 6) = 0;
  uVar1 = getppid();
  __sprintf_chk(&local_128,1,0xff,"/proc/%d/cmdline",(ulong)uVar1);
  __stream = fopen((char *)&local_128,"r");
  if (__stream != (FILE *)0x0) {
    fread(&local_12f,1,6,__stream);
    fclose(__stream);
    pcVar2 = strstr((char *)&local_12f,"gdb");
    if (pcVar2 == (char *)0x0) {
      pcVar2 = strstr((char *)&local_12f,"strace");
      if (pcVar2 == (char *)0x0) {
        pcVar2 = strstr((char *)&local_12f,"ltrace");
        if (pcVar2 == (char *)0x0) {
          if (local_20 == *(long *)(in_FS_OFFSET + 0x28)) {
            return;
          }
                    /* WARNING: Subroutine does not return */
          __stack_chk_fail();
        }
      }
    }
    puts("I don\'t like your father ");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  puts("Failed to get name ");
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```

This last one seems like a doozy, but if we take a quick look we can see names like **"strace", "gdb", "ltrace"***, which should give us a good idea of what it's trying to do: 

**It's looking for a debugger** or tracer of sorts. More specifically, it uses a /proc/\<pid\>/cmdline, which stores the string used to run the program from the shell, so in case you tried to run it with gdb as follows: "gdb ./challenge2", you would fail miserably, and the program will halt, stating it's boiling hatred towards your parent.

*Note: It may be possible to circumvent these safeguards if no other safeguards were in place by using for example a symlink to gdb.*

After noting that, we can move on to disect the other function.
Let's focus on the body of the function:
```c
  __ptr = malloc(10);
  __stream = fopen("/dev/random","rb");
  if (__stream != (FILE *)0x0) {
    uVar2 = 6;
    sVar1 = fread(__ptr,1,10,__stream);
    if (sVar1 == 10) {
      *param_1 = __ptr;
      uVar2 = 0;
    }
    fclose(__stream);
    return uVar2;
  }
  return 5;
```
**This function allocates a buffer of size 10, then reads into that buffer from /dev/random.**
It returns 0 on success and 5 or 6 on failure.

Let's paraphrase this function:
```c
uint8_t generateRandomKey(void **key_pointer)

{
  void *key;
  FILE *random_file;
  size_t numRead;
  uint8_t ret;
  
  key = malloc(10);
  random_file = fopen("/dev/random","rb");
  if (random_file != (FILE *)0x0) { // Ensures the file pointer is not the null pointer.
    ret = 6;
    numRead = fread(key, 1, 10, random_file);
    if (numRead == 10) {
      *key_pointer = key;
      ret = 0;
    }
    fclose(random_file);
    return ret;
  }
  ret = 5
  return ret;
}
```
Okay. Much more readable. So now we can clearly see what this function is doing.
Before we can continue, we need to understand why this is reading from /dev/random, and why might this file be able to provide us with a random key.

### /dev/random
So what is /dev/random? According to the Linux Manual:

       The character special files /dev/random and /dev/urandom provide an 
       interface to the kernel's random number generator.

       The random number generator gathers environmental noise from device
       drivers and other sources into an entropy pool.  The generator also
       keeps an estimate of the number of bits of noise in the entropy pool.
       From this entropy pool, random numbers are created.
Basically, the kernel gives us a promise: **If you read from /dev/random and /dev/urandom, you'll get random data.**
This is not *entirely* accurate. To understand why, we need to understand how the kernel generates these random numbers.

The kernel has something called an *"entropy pool"*: This is a pool of data gathered from things like keyboard presses, mouse movements and other things happening in and around the OS to create a pool of psuedorandom data. This data, which is mostly random, is then used to generate the data in /dev/random and /dev/urandom. This data takes time to replenish, and here comes the major difference between /dev/random and /dev/urandom:

/dev/random may "block", while /dev/urandom is "non-blocking". Generating random data uses up entropy from the entropy pool. When reading from /dev/random, if no data is available, the program will hold, and wait for more data to become available.
On the other hand, /dev/urandom will not. Why? The reason has to do with how /dev/urandom generates its random data. /dev/urandom uses the entropy pool to generate a seed, which it feeds into an RNG (Random Number Generator/Generation) algorithm. /dev/urandom will use the entropy pool when enough is entropy available in order to replenish it's seed.

Note: [There's a bug** in the linux kernel](https://security.stackexchange.com/a/172724)
(Not really though)

### Discovering main
Armed with the knowledege of how /dev/random works, we can now try to complete our analysis of the binary.
If you've been paying attention, you'll have seen that although we've found a few useful function, we're yet to find our main function.

Looking through the list of symbols Ghidra was able to find, we can't see anything that looks like our main function. A handy trick we can use is to try and find main by using it's callees: If we know generateRandomKey is going to be called at some point, we can try to find out who's calling it. If we look at the references to the function, we can find one reference at address 0x00100e3c. If we jump to that address, Ghidra seems to be able to recover some sort of function, and provides us with the following decompiled C:
```c
ulong UndefinedFunction_00100e00(void)

{
  uint uVar1;
  int iVar2;
  char *unaff_RBX;
  ulong uVar3;
  long in_FS_OFFSET;
  char *in_stack_00000000;
  long in_stack_00000008;
  
  DAT_00302010 = (DAT_00302010 * 3 + 0x4119) % 0x539;
  if (DAT_00302010 != 0x26d) {
    puts("I saw what you did there... ");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  uVar1 = FUN_00100d10();
  uVar3 = (ulong)uVar1;
  if (uVar1 == 0) {
    iVar2 = strncmp(unaff_RBX,in_stack_00000000,10);
    if (iVar2 == 0) {
      puts("Great Success! ");
    }
    else {
      uVar3 = 1;
      puts("Please try again ");
    }
  }
  else {
    uVar3 = 1;
    puts("Failed to get key! ");
  }
  if (in_stack_00000008 == *(long *)(in_FS_OFFSET + 0x28)) {
    return uVar3;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```
And there it is! We've found main!

Of course, we don't have much use for this as it is. We need to understand what it is it's doing.
Let's paraphrase a little:
```c
ulong main(void)
{
  uint uVar1;
  int iVar2;
  char *unaff_RBX;
  ulong uVar3;
  long in_FS_OFFSET;
  char *in_stack_00000000;
  long in_stack_00000008;
  
  DAT_00302010 = (DAT_00302010 * 3 + 0x4119) % 0x539;
  if (DAT_00302010 != 0x26d) {
    puts("I saw what you did there... ");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  
  zeroIfSuccess = generateRandomKey();
  ret = (ulong)uVar1;
  if (zeroIfSuccess == 0) {
    zeroIfEqual = strncmp(unaff_RBX,in_stack_00000000,10); // Some sort of string comparison.
    if (zeroIfEqual == 0) {
      puts("Great Success! ");
    }
    else {
      ret = 1;
      puts("Please try again ");
    }
  }
  else {
    ret = 1;
    puts("Failed to get key! ");
  }
  
  
  if (in_stack_00000008 == *(long *)(in_FS_OFFSET + 0x28)) {
    return ret;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}

```
For now, it's probably safe to ignore the top and bottom parts. One of them is an automatically inserted check to protect against buffer overflow attacks (or any other stack smashing shenaningans), and the other is most likely an integrity check.

Upon closer inspection, we can see the function is comparing 2 strings, and printing "Great Success" if they are equal.
It's safe to assume that these are our input and the generated key, and yet there's something off about this... There are a few indicators that point to us not getting the full picture here. More specifically, theses 2 lines are a huge red flag:
```c
zeroIfSuccess = generateRandomKey();
```
```c
zeroIfEqual = strncmp(unaff_RBX,in_stack_00000000,10);
```
Why, might you ask?

Well, let's go through this: The first line calls generateRandomKey, a function whose signature we already know:
```c
uint8_t generateRandomKey(char** key_pointer);
```
Weird, there seems to be a signature mismatch... Perhaps a look at the assembly will help us understand the call better:
```asm
        00100e39 MOV        RDI,RSP
        00100e3c CALL       generateRandomKey
```
We can clearly see here that RSP is moved into RDI before calling... weird.
We'll get back to this shortly

Let's look at 
