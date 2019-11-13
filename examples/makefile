CFLAGS=-std=c11 -pedantic-errors

compress: compress.c ../compressor.c ../jsmn.c ../fragmenter.c ../picocoap.c
	gcc -o compress compress.c ../compressor.c ../jsmn.c ../fragmenter.c ../picocoap.c -lm 

no-ack: no-ack.c ../compressor.c ../jsmn.c ../fragmenter.c ../picocoap.c timer.c
	gcc -o no-ack no-ack.c ../compressor.c ../jsmn.c ../fragmenter.c ../picocoap.c timer.c -lm -lpthread
	
clean :
	rm compress no-ack no-ack-test

all: no-ack compress