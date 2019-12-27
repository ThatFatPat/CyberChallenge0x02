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
