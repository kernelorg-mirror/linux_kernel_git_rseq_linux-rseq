CFLAGS += -O2 -Wall -g -I./ -I../../../../usr/include/ -L./ -Wl,-rpath=./

TEST_GEN_PROGS = basic_cpu_opv_test libcpu-op.so

ALL: $(TEST_GEN_PROGS)

libcpu-op.so: cpu-op.c cpu-op.h
	$(CC) $(CFLAGS) -shared -fPIC $< -o $@

# Own recipe because we only want to build against 1st prerequisite, but
# still track changes to header files.
%: %.c libcpu-op.so cpu-op.h
	$(CC) $(CFLAGS) $< -lcpu-op -o $@

include ../lib.mk
