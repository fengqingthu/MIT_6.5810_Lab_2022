ifeq ($(origin SPDK_ROOT),undefined)
$(error Please define SPDK_ROOT)
endif

ifeq ($(origin DPDK_ROOT),undefined)
$(error Please define DPDK_ROOT)
endif

INC = -I$(SPDK_ROOT)/include -I$(DPDK_ROOT)/build/include
SPDK_LIB_DIR=$(SPDK_ROOT)/build/lib
DPDK_LIB_DIR=$(DPDK_ROOT)/build/lib/x86_64-linux-gnu
SPDK_PKG_CONFIG_PATH = $(SPDK_ROOT)/build/lib/pkgconfig
DPDK_PKG_CONFIG_PATH = $(DPDK_ROOT)/build/lib/x86_64-linux-gnu/pkgconfig
SPDK_LIB = $(shell PKG_CONFIG_PATH="$(SPDK_PKG_CONFIG_PATH)" pkg-config --libs spdk_nvme spdk_vmd spdk_env_dpdk)
DPDK_LIB = $(shell PKG_CONFIG_PATH="$(DPDK_PKG_CONFIG_PATH)" pkg-config --libs libdpdk)
SYS_LIB = $(shell PKG_CONFIG_PATH="$(SPDK_PKG_CONFIG_PATH)" pkg-config --libs --static spdk_syslibs)
CFLAGS = -march=native
LIBS = -Wl,--whole-archive $(SPDK_LIB) -Wl,--no-whole-archive $(DPDK_LIB) $(SYS_LIB)

build: main

main: main.c
	$(CC) $(CFLAGS) $(INC) main.c -o main $(LIBS)

run: main
	sudo LD_LIBRARY_PATH=$(SPDK_LIB_DIR):$(DPDK_LIB_DIR):$(LD_LIBRARY_PATH) ./main

clean:
	rm -f main
