SUBDIRS = ./glibc_bench ./glibc_debug ./simple_test

.PHONY:all
all:
	@list='$(SUBDIRS)';for subdir in $$list; do \
		make -C $$subdir; \
	done
	
.PHONY:clean
clean:
	rm -rf ../bin/*