EXTRA_CFLAGS +=
APP_EXTRA_FLAGS:= -O2 -ansi -pedantic
KERNEL_SRC:= /lib/modules/$(shell uname -r)/build
SUBDIR= $(PWD)
GCC:=gcc
RM:=rm

.PHONY : clean

all: clean modules work monitor

obj-m:= kechenl3_MP3.o

modules:
	$(MAKE) -C $(KERNEL_SRC) M=$(SUBDIR) modules

work: work.c
	$(GCC) -o work work.c

monitor: monitor.c
	$(GCC) -o monitor monitor.c

clean:
	$(RM) -f work monitor *~ *.ko *.o *.mod.c Module.symvers modules.order
