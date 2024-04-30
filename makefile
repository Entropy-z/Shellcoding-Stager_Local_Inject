MAKEFLAGS += -s

all: shellcode extract Ldr

shellcode:
	@echo "Compiling Shellcode..."
	cd Shellcode && make shellcode

extract:
	@echo "Extracting Shellcode..."
	cd Shellcode && make extract

Ldr:
	@echo "Compiling Ldr..."
	cd Ldr && make Ldr

.PHONY: shellcode extract Ldr
