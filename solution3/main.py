import os
import subprocess
import time

if os.getuid() != 0:
    print("\n===============")
    print("Please run me as root!")
    print("===============\n")
    exit(0)

print("\n===============")
print("Creating chroot directory")
print("===============\n")
os.system("""mkdir chroot_jail &&
             cd chroot_jail &&
             mkdir bin dev lib lib/x86_64-linux-gnu lib64 proc &&
             mount --bind /proc ./proc &&
             cp ../challenge2 bin &&
             cp /lib/x86_64-linux-gnu/libc.so.6 lib/x86_64-linux-gnu &&
             cp /lib64/ld-linux-x86-64.so.2 lib64
             mknod dev/random c 1 5
             """)

print("\n===============")
print("Executing program")
print("===============\n")
challegne2 = subprocess.Popen(
    ["sudo", "chroot", "chroot_jail", "bin/challenge2"], stdin=subprocess.PIPE)
time.sleep(1)
challegne2.communicate(
    bytes("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", encoding="utf-8"))

print("\n===============")
print("Removing chroot directory")
print("===============\n")
os.system("""umount chroot_jail/proc &&
             rm -rf chroot_jail
             """)
