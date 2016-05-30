CFLAGS += -O2 -Wall -g -I./ -I../cpu-opv/ -I../../../../usr/include/ -L./ -Wl,-rpath=./
LDLIBS += -lpthread

TEST_GEN_PROGS = basic_test basic_percpu_ops_test param_test \
		librseq.so libcpu-op.so

ALL: $(TEST_GEN_PROGS)

librseq.so: rseq.c rseq.h rseq-*.h
	$(CC) $(CFLAGS) -shared -fPIC $< $(LDLIBS) -o $@

libcpu-op.so: ../cpu-opv/cpu-op.c ../cpu-opv/cpu-op.h
	$(CC) $(CFLAGS) -shared -fPIC $< $(LDLIBS) -o $@

# Own recipe because we only want to build against 1st prerequisite, but
# still track changes to header files.
%: %.c librseq.so libcpu-op.so rseq.h rseq-*.h ../cpu-opv/cpu-op.h
	$(CC) $(CFLAGS) $< $(LDLIBS) -lrseq -lcpu-op -o $@

TEST_PROGS = run_param_test.sh

include ../lib.mk
