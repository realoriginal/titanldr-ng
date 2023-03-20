CC_X64	:= x86_64-w64-mingw32-gcc
CC_X86	:= i686-w64-mingw32-gcc

CFLAGS	:= $(CFLAGS) -Os -fno-asynchronous-unwind-tables -nostdlib 
CFLAGS 	:= $(CFLAGS) -fno-ident -fpack-struct=8 -falign-functions=1
CFLAGS  := $(CFLAGS) -s -ffunction-sections -falign-jumps=1 -w
CFLAGS	:= $(CFLAGS) -falign-labels=1 -fPIC -Wl,-TSectionLink.ld
LFLAGS	:= $(LFLAGS) -Wl,-s,--no-seh,--enable-stdcall-fixup

OUTX64	:= Titan.x64.exe
OUTX86	:= Titan.x86.exe
BINX64	:= Titan.x64.bin
BINX86	:= Titan.x86.bin

all:
	@ nasm -f win32 asm/x86/Start.asm -o Start.x86.o
	@ nasm -f win64 asm/x64/Start.asm -o Start.x64.o
	@ nasm -f win32 asm/x86/GetIp.asm -o GetIp.x86.o
	@ nasm -f win64 asm/x64/GetIp.asm -o GetIp.x64.o
	@ $(CC_X86) *.c Start.x86.o GetIp.x86.o hooks/*.c hde/*32*.c -o $(OUTX86) $(CFLAGS) $(LFLAGS) -I.
	@ $(CC_X64) *.c Start.x64.o GetIp.x64.o hooks/*.c hde/*64*.c -o $(OUTX64) $(CFLAGS) $(LFLAGS) -I.
	@ python3 python3/extract.py -f $(OUTX86) -o $(BINX86)
	@ python3 python3/extract.py -f $(OUTX64) -o $(BINX64)

clean:
	@ rm -rf *.o
	@ rm -rf *.bin
	@ rm -rf *.exe
