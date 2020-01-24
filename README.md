# Cyber Challenge 0x02
This challenege has it's fair share of reversing, as well as general Linux knowledge.

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

`FUN_00100d10`:
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

`_INIT_1`:
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

**It's looking for a debugger** or tracer of sorts. More specifically, it uses a /proc/\<pid\>/cmdline, which stores the string used to run the program from the shell, so in case you tried to run it with gdb as follows: "gdb ./challenge2", you would fail miserably, and the program will halt, stating its boiling hatred towards your parent.

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


This blocking behavior explains why it may take the program time to "compute the key": Reading from /dev/random may slow down to a crawl if the kernel is out of entropy.

### Discovering main
Armed with the knowledege of how /dev/random works, we can now try to complete our analysis of the binary.
If you've been paying attention, you'll have seen that although we've found a few useful function, we've yet to find our main function.

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


Let's look at the second line:

The second line calls strncmp on two very weird variables... `unaff_RBX` and `in_stack_00000000`. These are helpful names provided by Ghidra, although they may not seem so at first. `unaff_RBX` most-likely stands for Unaffiliated RBX, pointing out the fact that RBX is not set anywhere in the function, and seems to be falling from the sky. The next variable, `in_stack_00000000`, has a similarly revealing name. `in_stack` points to the fact that the variable is just in the stack, and in contrast to function-local variables, which Ghidra marks as local_\<stack_offset\>, this one is just "in the stack", meaning it may not be in the scope of this function.

This may all seem confusing at first, but it ultimatly points to something. I'll admit, it took me a little while to find this, but this is what's happening here: parts of this function may have been fuzzed or otherwise messed with in such a way that Ghidra does not identify them as part of the function body. And sure enough, if we take a look just above 0x00100e00, where Ghidra thinks the function starts, we find this lovely section:
```asm
        00100d92 0f              ??         0Fh
        00100d93 1f              ??         1Fh
        00100d94 40              ??         40h    @
        00100d95 00              ??         00h
        00100d96 66              ??         66h    f
        00100d97 2e              ??         2Eh    .
        00100d98 0f              ??         0Fh
        00100d99 1f              ??         1Fh
        00100d9a 84              ??         84h
        00100d9b 00              ??         00h
        00100d9c 00              ??         00h
        00100d9d 00              ??         00h
        00100d9e 00              ??         00h
        00100d9f 00              ??         00h
        00100da0 55              ??         55h    U
        00100da1 53              ??         53h    S
        00100da2 48              ??         48h    H
        00100da3 89              ??         89h
        00100da4 fb              ??         FBh
        00100da5 48              ??         48h    H
        00100da6 83              ??         83h
        00100da7 ec              ??         ECh
        00100da8 18              ??         18h
        00100da9 64              ??         64h    d
        00100daa 48              ??         48h    H
        00100dab 8b              ??         8Bh
        00100dac 04              ??         04h
        00100dad 25              ??         25h    %
        00100dae 28              ??         28h    (
        00100daf 00              ??         00h
        00100db0 00              ??         00h
        00100db1 00              ??         00h
        00100db2 48              ??         48h    H
        00100db3 89              ??         89h
        00100db4 44              ??         44h    D
        00100db5 24              ??         24h    $
        00100db6 08              ??         08h
        00100db7 31              ??         31h    1
        00100db8 c0              ??         C0h
        00100db9 48              ??         48h    H
        00100dba c7              ??         C7h
        00100dbb 04              ??         04h
        00100dbc 24              ??         24h    $
        00100dbd 00              ??         00h
        00100dbe 00              ??         00h
        00100dbf 00              ??         00h
        00100dc0 00              ??         00h
        00100dc1 e8              ??         E8h
        00100dc2 4a              ??         4Ah    J
        00100dc3 fb              ??         FBh
        00100dc4 ff              ??         FFh
        00100dc5 ff              ??         FFh
        00100dc6 31              ??         31h    1
        00100dc7 c9              ??         C9h
        00100dc8 31              ??         31h    1
        00100dc9 d2              ??         D2h
        00100dca 89              ??         89h
        00100dcb c6              ??         C6h
        00100dcc 31              ??         31h    1
        00100dcd ff              ??         FFh
        00100dce 31              ??         31h    1
        00100dcf c0              ??         C0h
        00100dd0 e8              ??         E8h
        00100dd1 8b              ??         8Bh
        00100dd2 fb              ??         FBh
        00100dd3 ff              ??         FFh
        00100dd4 ff              ??         FFh
        00100dd5 48              ??         48h    H
        00100dd6 83              ??         83h
        00100dd7 f8              ??         F8h
        00100dd8 ff              ??         FFh
        00100dd9 74              ??         74h    t
        00100dda 25              ??         25h    %
        00100ddb 8b              ??         8Bh
        00100ddc 15              ??         15h
        00100ddd 2f              ??         2Fh    /
        00100dde 12              ??         12h
        00100ddf 20              ??         20h     
        00100de0 00              ??         00h
        00100de1 81              ??         81h
        00100de2 fa              ??         FAh
        00100de3 6d              ??         6Dh    m
        00100de4 02              ??         02h
        00100de5 00              ??         00h
        00100de6 00              ??         00h
        00100de7 74              ??         74h    t
        00100de8 50              ??         50h    P
                             LAB_00100de9                                    XREF[1]:     00100e37(j)  
        00100de9 48 8d 3d        LEA        RDI,[s_I_saw_what_you_did_there..._00100fa6]     = "I saw what you did there... "
                 b6 01 00 00
        00100df0 e8 fb fa        CALL       puts                                             int puts(char * __s)
                 ff ff
        00100df5 31 ff           XOR        EDI,EDI
        00100df7 e8 94 fb        CALL       exit                                             void exit(int __status)
                 ff ff
                             -- Flow Override: CALL_RETURN (CALL_TERMINATOR)
        00100dfc 0f              ??         0Fh
        00100dfd 1f              ??         1Fh
        00100dfe 40              ??         40h    @
        00100dff 00              ??         00h
```
I don't know about you, but to me it seems oddly suspicious that this huge piece of data is just sitting there, in the middle of a code section. Let's then try and decompile it, shall we? If we highlight this section and press D, Ghidra will try to disassemble the code.

Here's how our main looks after the disassembly:
```c
ulong FUN_00100da0(char *param_1)

{
  uint uVar1;
  int iVar2;
  long lVar3;
  ulong uVar4;
  long in_FS_OFFSET;
  char *local_28;
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  local_28 = (char *)0x0;
  uVar1 = getpid();
  lVar3 = ptrace(PTRACE_TRACEME,(ulong)uVar1,0);
  if (lVar3 == -1) {
    DAT_00302010 = (DAT_00302010 * 3 + 0x4119) % 0x539;
  }
  if (DAT_00302010 != 0x26d) {
    puts("I saw what you did there... ");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  uVar1 = FUN_00100d10(&local_28);
  uVar4 = (ulong)uVar1;
  if (uVar1 == 0) {
    iVar2 = strncmp(param_1,local_28,10);
    if (iVar2 == 0) {
      puts("Great Success! ");
    }
    else {
      uVar4 = 1;
      puts("Please try again ");
    }
  }
  else {
    uVar4 = 1;
    puts("Failed to get key! ");
  }
  if (local_20 == *(long *)(in_FS_OFFSET + 0x28)) {
    return uVar4;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```
This is much more like it! No more unresolved references, now we can get to work.

Let's reapply the changes we've made, adding in bits we've learned from before:
```c
ulong main(char *param_1)

{
  uint zeroIfSuccess;
  int iVar1;
  long lVar2;
  ulong ret;
  long in_FS_OFFSET;
  char *key;
  
  key = (char *)0x0;
  pid = getpid();
  ptrace_res = ptrace(PTRACE_TRACEME,(ulong)pid,0);
  if (ptrace_res == -1) {
    DAT_00302010 = (DAT_00302010 * 3 + 0x4119) % 0x539;
  }
  if (DAT_00302010 != 0x26d) {
    puts("I saw what you did there... ");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  zeroIfSuccess = generateRandomKey(&key);
  ret = (ulong)zeroIfSuccess;
  if (zeroIfSuccess == 0) {
    zeroIfEqual = strncmp(param_1,key,10);
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
  return ret;
 ```
Very nice! We'll remove the stack guard to simplify the function a little.


We can now clearly see the flow of the program, and now we can figure out what that integrity check was all about.
The function calls ptrace, a syscall which is used for many different requests regarding the debugging of a program. You can use it to debug a program step-by-step, or to figure out if you are being debugged by ptrace. By calling ptrace with the `PTRACE_TRACEME` constant we can learn if we are being traced by ptrace. If so, the function will not change a certain global variable to match the data required for the program to keep executing. Basically, if ptrace doesn't return -1, signaling we are not being traced, the program will exit.

*Note: Remember how I said that you could circumvent the protections by using a symlink? This is another safeguard against that. To solve this you will have to make sure to break before the check and modify the global variable so the program doesn't quit.*

With that out of the way, let's finish analyzing main.
Basically, main boils down to this piece of code:
```c
  zeroIfSuccess = generateRandomKey(&randomKey);
  ret = (ulong)zeroIfSuccess;
  if (zeroIfSuccess == 0) {
    zeroIfEqual = strncmp(userKey,randomKey,10);
    if (zeroIfEqual == 0) {
      puts("Great Success! ");
    }
    else {
      ret = 1;
      puts("Please try again ");
    }
  }
```
It's fair to assume that `param_1` represents the user input in this case, so let's name it `userKey` from now on.
Also, for our sanity, let's refer to `key` as `randomKey` from now on.

If we had to summarize main in one sentence then, it would be that:

**`main` takes a user-specified string as input, and compares it to random data it gets from /dev/random**

Before we move on, it's important to note that this is not actually main.
This function is called by another hidden function that we need to manually disassemble, which looks something like this:
```c

undefined  [16] UndefinedFunction_00100b10(void)

{
  uint uVar1;
  long lVar2;
  char *__s;
  char *pcVar3;
  ulong uVar4;
  undefined8 uStack24;
  
  uVar1 = getpid();
  lVar2 = ptrace(PTRACE_TRACEME,(ulong)uVar1,0,0);
  if (lVar2 == 0) {
    uVar4 = 4;
    DAT_00302010 = (DAT_00302010 + 1 >> 1) % 3;
    __s = (char *)malloc(10);
    if (__s != (char *)0x0) {
      puts("Please, enter the key: ");
      pcVar3 = fgets(__s,10,(FILE *)0x0);
      if (pcVar3 == (char *)0x0) {
        puts("no input, exiting! ");
      }
      else {
        main(__s);
      }
      uVar4 = (ulong)(pcVar3 == (char *)0x0);
      free(__s);
    }
    return CONCAT88(uStack24,uVar4);
  }
  puts("Don\'t Debug me! ");
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```
Basically, this function sets up the ptrace safeguard, gets a 10 char string from the user as input (including the null terminator) and calls our "main".
To account for this, we'll call this function "real main", although it won't prove very important here.


## Breaking the randomness
/dev/random is specifically designed to prevent us from being able to craft some sort of known output. After reading around, it becomes obvious that controlling the ouput of random through traditional means is not a possibility. What I mean by that is that by design, there is no interface that allows you to choose or influence the data /dev/random will generate.

If we've established that as a baseline, we can try to work from here and find ways to prevent the program from being able to access the real /dev/random, or at least it's random data.

### 1st Solution: LD_PRELOAD
After looking around for a bit, I've stumbled upon a solution. The obvious one in this case. If we could affect the return values of the syscalls we are using, we can easily control the program. The most naive solution would be to work straight from the comparison: **If we can somehow make `strncmp` return 0, we can beat the security of the program.**

By researching online a little we can easily find references to some mysterious environment variable called LD_PRELOAD.
A very nice blogpost written by Peter Goldsborough about the topic can be found [here](http://www.goldsborough.me/c/low-level/kernel/2016/08/29/16-48-53-the_-ld_preload-_trick/).
The short and long of it is that LD_PRELOAD is a way of telling the linker that when loading the program, it should first look for symbols it needs in the file specified by LD_PRELOAD, and only then should it try to find the load symbols from other places, such as the C standard library. This trick allows us to create our own syscalls, and "hook" a specific syscall from the program.

And so, using this technique, we can hook the strncmp syscall as follows:
```c
size_t strncmp(char* str1, char* str2, size_t n){
    return 0;
}
```
If we compile this into `strncmp.so` (See solution1 in the repo for a more detailed example using `fopen`), we can then use LD_PRELOAD to load the program like so:
```console
$ LD_PRELOAD=./strncmp.so ./challenge2
Please, enter the key:
BLABLA
Great Success!
```
We did it!

Alas, if we refer back to the instructions:

    Patching the program to accept Any Key won’t be accepted as a solution!

So we did it, but not really. Maybe we can try hooking a different syscall? We could, but now this vector of attack already feels too hacky...

Let's try it anyway, just for fun xD. Let's hook the `fopen` syscall:

The following code comes from solution1/fopen.c
```c
#define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>


FILE* fopen ( const char * filename, const char * mode ){
    FILE *(*original_fopen)(const char*, const char*);
    original_fopen = dlsym(RTLD_NEXT, "fopen");
    FILE* ret;
    int cmp = strcmp(filename, "/dev/random");
    if (!cmp){
        ret = (*original_fopen)("./random_chars", "rb");
    }
    else {
        ret = (*original_fopen)(filename, mode);
    }
    return ret;
}
```
This code was modified from [here](https://catonmat.net/simple-ld-preload-tutorial-part-two).
Basically, we construct a function pointer to the original `fopen`:
```c
FILE *(*original_fopen)(const char*, const char*);
original_fopen = dlsym(RTLD_NEXT, "fopen");
```
And the rest of the function refers only /dev/random to our crafted file: `./random_chars`, which looks a little something like this:
```
AAAAAAAAA\x00
```
Where `\x00` is the null-terminator.

If we then run the program using `LD_PRELOAD=./fopen.so`, we can ensure that the key that will be read by the program is just a string of 9 'A's, followed by the null terminator. Which means we should be able to crack the program by inserting 10 'A's.

```console
$ LD_PRELOAD=./fopen.so ./challenge2
Please, enter the key
AAAAAAAAAA
Great Succcess!
```
Success! This feels a little less hacky, but it's still a little off. Let's try solving this a different way.

## 2nd Solution: Replacing /dev/random
Let's be reckless for a moment. Let's say we don't care about the random output from /dev/random for any other program on the system. While reading around, I found [this](https://everything2.com/title/Compromising+%252Fdev%252Frandom) lovely forum thread, containing the following, slightly modified message:

    $ sudo rm /dev/random
    $ sudo mknod /dev/random c 1 5
    
    You can't trust the random number generator on any system you don't control.
    The shell commands above delete /dev/random and then recreate it - but 
    instead of using the device numbers for a character device that outputs 
    random data from the entropy pool (1,8), we use the numbers for a device 
    that spits out nothing but zero (1,5). So when you think you are generating
    a 4096 bit secure key using genuine random data, you are just getting four 
    thousand zeros. And even if your software checks for something like this, 
    there are more sophisticated ways to generate random looking data that isn't.

Oh my, that seems like something we can take advantage of! Sure enough, if we try to run the following script, instead of the following happening:
```console
user@pc$ head -c10 /dev/random       # Print the top 10 characters in random
A7-Zh5;8a]
user@pc$
```
We get the following output:
```console
user@pc$ sudo rm /dev/random
user@pc$ sudo mknod /dev/random c 1 5
user@pc$ head -c10 /dev/random
user@pc$
```
It seems to print nothing... Hmmm. Oh wait, that's good! We have to remember what zeros are: zeros are null terminators, and null terminators are non-printable characters. Not only are they non-printable, but they are also zero-width, thus making it seem like nothing was printed, when in fact, we had achieved the desired result!

Now we just have to make sure to feed our program 10 of these null terminators, and wait for the magic to happen.
Let's do that:
```console
$ echo -n -e "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" | ./challenge2
Please, enter the key:
Great Success!
```
We did it! We've found another way to crack the program!

Now, in order to ensure we don't leave /dev/random broken, we need to restore it. If we look back at the forum post:

    The shell commands above delete /dev/random and then recreate it - but 
    instead of using the device numbers for a character device that outputs 
    random data from the entropy pool (1,8), we use the numbers for a device 
    that spits out nothing but zero (1,5).
    
And we see the following command:
```console
$ sudo mknod /dev/random c 1 5
```
According to the post, (1,5) is responsible for generating zeros (used by /dev/zero), and (1, 8) is used for /dev/random. So we can reconstruct /dev/random by running the following commands:
```console
user@pc$ sudo rm /dev/random
user@pc$ sudo mknod /dev/random c 1 8
```
And we got our computer back to a fully-functioning state. Phew.

## 3rd Soultion: We Chrootin' Boys
Now that we have a pretty good understanding of how to circumvent the randomness, let's present another way of going about it: `chroot`. As helpfully layed out by HowToGeek writer Dave McKay:

    With chroot you can set up and run programs or interactive shells such as Bash in an encapsulated filesystem that is   
    prevented from interacting with your regular filesystem. Everything within the chroot environment is penned in and       
    contained. Nothing in the chroot environment can see out past its own, special, root directory without escalating to     
    root privileges. That has earned this type of environment the nickname of a chroot jail. 
    
You can find the source [here](https://www.howtogeek.com/441534/how-to-use-the-chroot-command-on-linux/). In this simple guide, he lays out a very simple manner in which we can create a "chroot jail". For those of us who prefer a video guide, one can be found [here](https://www.youtube.com/watch?v=myakVWvRmfc), although you should probably use the first one, as I feel it just does it better.

I fully encourage you to check one of these guides out and follow along, as "chroot"-ing is a very important skill that may come in handy at some point. Locking a program in an environment where we control all the variables may prove very productive.

Now that we have a vauge idea of how `chroot` works, we can apply what we've already learned here. **The basic idea is that instead of deleting the system's /dev/random, we can trick the program into using a different filesystem, where we control /dev/random**. Let's do that.

First we need to create a chroot environment:
```console
$ chr=/home/\<USER\>/chroot_jail
$ mkdir -p $chr
$ mkdir -p $chr/{bin,lib,lib64}
$ cd $chr
$ cp /path/to/challange2 bin
```
Now that we've created the directories and copied over our binary, we'll copy over our dependencies. We'll use `ldd` to find them:
```console
$ ldd challenge2
	linux-vdso.so.1 (0x00007ffd64cd3000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fadb15d7000)
	/lib64/ld-linux-x86-64.so.2 (0x00007fadb1bcb000)
```
And so, let's copy those over into the appropriate directories as specified by the path (We don't need `linux-vdso`):
```console
$ cp /lib/x86_64-linux-gnu/libc.so.6 $chr/lib/x86_64-linux-gnu/libc.so.6
$ cp /lib64/ld-linux-x86-64.so.2 $chr/lib64/ld-linux-x86-64.so.2
```
And now we can simply create another reference to the (1,5) special character device using mknod:
```console
$ mknod $chr/dev/random c 1 5
```
And that's it! Now we can run the binary. Let's try that:
```console
$ cd $chr
$ echo -n -e "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" | sudo chroot $chr bin/challenge2
Failed to get name
```
Oh... What's going on here? Something's off. Let's try to understand what happened. The best way to do this is to go back to the reversed binary and look at the code that prints this line. Let's look at `\_INIT_1`:
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
Yuck. Let's try to boil this down only to the necessary `if` statement, and try to beautify it a bit:
```c
  ppid = getppid();
  __sprintf_chk(&local_128, 1, 0xff, "/proc/%d/cmdline", ppid);
  cmdline = fopen((char *)&local_128, "r");
  if (cmdline != (FILE *)0x0) {
     /* Additional Checks */
  }
  puts("Failed to get name ");
```
Ok. This is a little better. If we don't dig too deep, and look at the general outline of the code, we can try to understand what's happening here, and why our program might fail. The program tries to access /proc/<ppid>/cmdline to get the shell command used to run it, but for some reason it isn't able to get it.
  
If we think back to the definition of a `chroot` jail:
  
    Everything within the chroot environment is penned in and       
    contained. Nothing in the chroot environment can see out past its own,
    special, root directory without escalating to root privileges.
    
The reason for this failure should become clear right about now, as we realize that we forgot to give the program access to `/proc`, and since it cannot access anything outside of it's fake root directory, it can't get access to `proc`.
We can fix this by mounting `/proc` in out chroot directory:
```c
$ sudo mount --bind /proc $chr/proc
```
Now, if we run our program:
```console
$ echo -n -e "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" | sudo chroot $chr bin/challenge2
Please, enter the key
Great Success!
```
And there we go! We've found another way to solve the challenge.

It's important to remember to also unmount our `proc` directory when we're done with it using `umount`:
```console
$ sudo umount $chr/proc
```

## Closing Words
Thank you for taking the time to read through this write-up. I hope this has been informative and helpful in understanding how to solve this challenge, and the concepts behind it.

**ALL OF THE PRESENTED SOLUTIONS ARE AVAILABLE AS PYTHON3 SCRIPTS ON THE REPOSITORY**

For any questions, you're always welcome to contact me at idoshav@gmail.com
