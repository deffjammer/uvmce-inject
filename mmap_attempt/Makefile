
FLAGS += -D__KERNEL__ -DMODULE -g

obj-m += mmap_simple_kernel.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean


