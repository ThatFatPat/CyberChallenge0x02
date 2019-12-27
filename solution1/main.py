import subprocess
import os

subprocess.call(["gcc", "-fPIC", "-shared", "-o", "fopen.so", "fopen.c", "-ldl"])
print("=============")
print("When prompted for a key, please enter A * 10 (\"AAAAAAAAAA\")")
print("=============")
os.system("LD_PRELOAD=./fopen.so ./challenge2")

