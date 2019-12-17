CFLAGS=-std=c11 -pedantic-errors

compress: compress.c ../compressor.c ../jsmn.c ../fragmenter.c ../picocoap.c
	gcc -o compress compress.c ../compressor.c ../jsmn.c ../fragmenter.c ../picocoap.c -lm

# icmpv6: icmpv6.c ../compressor.c ../jsmn.c ../fragmenter.c ../picocoap.c uip/net/ipv6/uip6.c timer.c
#	gcc -o icmpv6 icmpv6.c ../compressor.c ../jsmn.c ../fragmenter.c ../picocoap.c uip/net/ipv6/uip6.c timer.c -lm -lpthread

fragment: fragment.c ../compressor.c ../jsmn.c ../fragmenter.c ../picocoap.c timer.c
	gcc -o fragment fragment.c ../compressor.c ../jsmn.c ../fragmenter.c ../picocoap.c timer.c -lm -lpthread
	
clean :
	rm compress fragment #icmpv6

all: fragment compress