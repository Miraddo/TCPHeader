run:
	clang -O2 -Wall -target bpf -c detector/detector.c -o detector.bpf.o
	gcc detector/loader.c -o loader -lbpf
	sudo ./loader