
FLAGS += -D__KERNEL__ -DMODULE -g
#obj-m += mymodule.o
#mymodule-objs := ./src/mymodule.o ./src/mymodule_func.o

obj-m += uv_mce_inject.o
#module-objs := ./uv_mce_inject.o ./k_dlook.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean


