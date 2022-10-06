@echo off

nasm -f win32 %1.asm -o %1.o
ld -m i386pe %1.o -o %1.exe
del %1.o
echo compilation terminated ....