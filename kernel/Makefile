
FLAGS += -D__KERNEL__ -DMODULE -g

obj-m += uv_mce_inject.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean


