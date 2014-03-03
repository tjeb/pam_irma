.PHONY: install do nfc pcsc install_pcsc install_nfc clean

all: nfc pcsc

pam_irma_nfc.so:
	g++ -fPIC -o pam_irma_nfc.o -c pam_irma.cpp `pkg-config --cflags libnfc` -DUSE_NFC
	g++ -shared -o pam_irma_nfc.so pam_irma_nfc.o -lpam -lsilvia `pkg-config --libs --cflags libnfc`
	rm -f pam_irma_nfc.o

pam_irma_pcsc.so:
	g++ -fPIC -o pam_irma_pcsc.o -c pam_irma.cpp `pkg-config --cflags libpcsclite` -DUSE_PCSC
	g++ -shared -o pam_irma_pcsc.so pam_irma_pcsc.o -lpam -lsilvia `pkg-config --libs --cflags libpcsclite`
	rm -f pam_irma_pcsc.o

install: install_nfc install_pcsc

install_pcsc: pam_irma_pcsc.so
	sudo cp pam_irma_pcsc.so /usr/lib64/security/pam_irma_pcsc.so

install_nfc: pam_irma_nfc.so
	sudo cp pam_irma_nfc.so /usr/lib64/security/pam_irma_nfc.so

clean:
	rm -f *.so
	rm -f *.o
