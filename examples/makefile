CFLAGS=-std=c11 -pedantic-errors

compress: compress.c ../compressor.c ../jsmn.c ../fragmenter.c ../picocoap.c ../bit_operations.c
	gcc -g -o compress compress.c ../compressor.c ../jsmn.c ../fragmenter.c ../picocoap.c ../bit_operations.c -lm
	
lwm2m: lwm2m.c ../compressor.c ../jsmn.c ../fragmenter.c ../picocoap.c ../bit_operations.c
	gcc -g -o lwm2m lwm2m.c ../compressor.c ../jsmn.c ../fragmenter.c ../picocoap.c ../bit_operations.c -lm

fragment: fragment.c ../compressor.c ../jsmn.c ../fragmenter.c ../picocoap.c ../bit_operations.c timer.c
	gcc -g -o fragment fragment.c ../compressor.c ../jsmn.c ../fragmenter.c ../picocoap.c ../bit_operations.c timer.c -lm -lpthread
	
interop: interop.c ../compressor.c ../jsmn.c ../fragmenter.c ../picocoap.c ../bit_operations.c
	gcc -g -o interop interop.c ../compressor.c ../jsmn.c ../fragmenter.c ../picocoap.c ../bit_operations.c timer.c -lm -lpthread
	
clean:
	rm compress fragment lwm2m interop

all: fragment compress lwm2m interop