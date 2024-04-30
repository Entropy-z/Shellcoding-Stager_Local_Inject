MAKEFLAGS += -s

CCX64     = x86_64-w64-mingw32-gcc.exe
NASM 	  = nasm.exe

OUTLDR   = ../Ldr/bin/shellcode.bin

OUTASM    = bin/entry.o
OUT 	  = bin/shellcode.exe
BIN       = bin
CORE 	  = $(wildcard src/core/*.c)
SRC       = src
INC		  = -Iinclude
SCRIPTS   = scripts

	## '-Os'        optimize for size
	## '-nostdlib'  Do not use the standard system startup files or libraries when linking
	## '-s'         Remove all symbols
	## '-fPIC'      Generate position-independent code (PIC)
	## '-w'         Suppress warnings.

CFLAGS    = -Os -nostdlib -s -fPIC -w -masm=intel 


shellcode: $(ASM_OBJ) $(C_OBJ)
	$(NASM) src/asm/entry.asm -f win64 -o $(OUTASM)
	$(CCX64) $(INC) $(CFLAGS) $(OUTASM) $(CORE) src/main.c -o $(OUT)
	rm $(OUTASM)
	@echo "[+] DONE!"

extract:
	@echo "[*] Extracting shellcode $(OUT)..."
	python $(SCRIPTS)/extract.py -f $(OUT) -o $(OUTLDR)
	@echo "[+] DONE!"

clean:
	@echo "[*] Cleaning up..."
	rm -f $(BIN)/*.o $(BIN)/*.exe $(BIN)/*.bin
	@echo "[+] DONE!"
