import os
import subprocess
import time

if os.getuid() != 0:
    print("===============")
    print("Please run me as root!")
    print("===============")
    exit(0)


print("\n===============")
print("Replacing /dev/random with /dev/zero")
print("===============\n")
os.system("rm /dev/random && ln -s /dev/zero /dev/random")

print("\n===============")
print("Running program!")
print("===============\n")
challegne2 = subprocess.Popen(["./challenge2"], stdin=subprocess.PIPE)
time.sleep(1)
challegne2.communicate(
    bytes("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", encoding="utf-8"))

print("\n===============")
print("Restoring /dev/random")
print("===============\n")
os.system("rm /dev/random && mknod /dev/random c 1 8")
