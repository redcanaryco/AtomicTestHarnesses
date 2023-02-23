all: do_setuid do_setgid

do_setuid: setuid.c
	gcc setuid.c -o $@

do_setgid: setgid.c
	gcc setgid.c -o $@

clean:
	rm -rf do_setuid do_setgid

.PHONY: clean
