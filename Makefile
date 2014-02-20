pam_irma.so:
	gcc -fPIC -c pam_irma.c
	gcc -shared -o pam_irma.so pam_irma.o -lpam
	rm -f pam_irma.o
