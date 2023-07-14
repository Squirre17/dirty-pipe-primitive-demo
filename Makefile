.PHONY: all module

all: exp

exp: exp.c
	@musl-gcc -static -no-pie -nostdlib -s sh.S -o shellcode -Wl,--strip-all
	@objcopy -O binary --only-section=.text ./shellcode fs/shellcode.bin
	@rm shellcode
	@gcc exp.c -o fs/exp -static -no-pie

module:
	make -C vuln_module
