# SPDX-License-Identifier: GPL-2.0+ OR MIT
CFLAGS += -O2 -Wall -g -I./ -I../rseq/ -I../../../../usr/include/ -L./ -Wl,-rpath=./
LDLIBS += -lpthread

# Own dependencies because we only want to build against 1st prerequisite, but
# still track changes to header files and depend on shared object.
OVERRIDE_TARGETS = 1

TEST_GEN_PROGS = basic_cpu_opv_test basic_percpu_ops_test \
		param_test param_test_skip_fastpath \
		param_test_benchmark param_test_compare_twice

TEST_GEN_PROGS_EXTENDED = librseq.so libcpu-op.so

TEST_PROGS = run_param_test.sh

include ../lib.mk

$(OUTPUT)/libcpu-op.so: cpu-op.c cpu-op.h
	$(CC) $(CFLAGS) -shared -fPIC $< $(LDLIBS) -o $@

$(OUTPUT)/librseq.so: ../rseq/rseq.c ../rseq/rseq.h ../rseq/rseq-*.h
	$(CC) $(CFLAGS) -shared -fPIC $< $(LDLIBS) -o $@

$(OUTPUT)/%: %.c $(TEST_GEN_PROGS_EXTENDED) ../rseq/rseq.h ../rseq/rseq-*.h cpu-op.h percpu-op.h
	$(CC) $(CFLAGS) $< $(LDLIBS) -lrseq -lcpu-op -o $@

$(OUTPUT)/param_test_skip_fastpath: param_test.c $(TEST_GEN_PROGS_EXTENDED) \
					../rseq/rseq.h ../rseq/rseq-*.h cpu-op.h percpu-op.h
	$(CC) $(CFLAGS) -DRSEQ_SKIP_FASTPATH $< $(LDLIBS) -lrseq -lcpu-op -o $@

$(OUTPUT)/param_test_benchmark: param_test.c $(TEST_GEN_PROGS_EXTENDED) \
					../rseq/rseq.h ../rseq/rseq-*.h cpu-op.h percpu-op.h
	$(CC) $(CFLAGS) -DBENCHMARK $< $(LDLIBS) -lrseq -lcpu-op -o $@

$(OUTPUT)/param_test_compare_twice: param_test.c $(TEST_GEN_PROGS_EXTENDED) \
					../rseq/rseq.h ../rseq/rseq-*.h cpu-op.h percpu-op.h
	$(CC) $(CFLAGS) -DRSEQ_COMPARE_TWICE $< $(LDLIBS) -lrseq -lcpu-op -o $@

