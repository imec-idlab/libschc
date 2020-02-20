CFLAGS=-std=c11 -pedantic-errors

compress: compress.c ../compressor.c ../jsmn.c ../fragmenter.c ../picocoap.c ../bit_operations.c
	gcc -g -o compress compress.c ../compressor.c ../jsmn.c ../fragmenter.c ../picocoap.c ../bit_operations.c -lm

fragment: fragment.c ../compressor.c ../jsmn.c ../fragmenter.c ../picocoap.c ../bit_operations.c timer.c
	gcc -g -o fragment fragment.c ../compressor.c ../jsmn.c ../fragmenter.c ../picocoap.c ../bit_operations.c timer.c -lm -lpthread
	
clean :
	rm compress fragment

all: fragment compress