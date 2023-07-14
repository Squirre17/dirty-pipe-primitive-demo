obj-m += vuln.o

KDIR := /home/squ/src-code-reading/linux-5.19 
# KDIR := /lib/modules/`uname -r`/build
# KDIR := /home/squ/prac/hbp-prac/linux-5.15.103

PWD := $(shell pwd)

.PHONY: default

default:
	make -C $(KDIR) M=$(PWD) modules  && \
	cp vuln.ko .. && \
	rm -rf .*.cmd *.symvers *.order *.ko *.mod* *.o

clean:
	rm -rf *.o \.* .cmd *.ko *.mod.c .tmp_versions