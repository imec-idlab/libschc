CFLAGS=-std=c11 -pedantic-errors

compress: compress.c ../compressor.c ../jsmn.c ../fragmenter.c ../picocoap.c
	gcc -o compress compress.c ../compressor.c ../jsmn.c ../fragmenter.c ../picocoap.c -lm 

fragment: fragment.c ../compressor.c ../jsmn.c ../fragmenter.c ../picocoap.c timer.c
	gcc -o fragment fragment.c ../compressor.c ../jsmn.c ../fragmenter.c ../picocoap.c timer.c -lm -lpthread
	
clean :
	rm compress fragment

all: fragment compress