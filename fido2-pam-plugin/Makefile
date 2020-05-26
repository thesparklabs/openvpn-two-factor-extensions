PREFIX=/usr/share/openvpn/pam-fido2
CFLAGS += -DPREFIX='"$(PREFIX)"' -DUSE_PAM_DLOPEN=1
LD_LIB_PATH += "-I."

OBJS = auth-pam-fido2.o pamdl.o utils.o

all: auth-pam-fido2.so

auth-pam-fido2.o: auth-pam-fido2.c
	$(CC) $(CFLAGS) $(LD_LIB_PATH) -fPIC -c auth-pam-fido2.c utils.c pamdl.c pamdl.h

auth-pam-fido2.so: auth-pam-fido2.o pamdl.o utils.o
	$(CC) -fPIC -shared -o auth-pam-fido2.so $(OBJS)

install: auth-pam-fido2.so
	mkdir -p $(DESTDIR)$(PREFIX)
	install -c auth-pam-fido2.so -m 755 $(DESTDIR)$(PREFIX)
	install -c auth-fido2.py -m 755 $(DESTDIR)$(PREFIX)

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/auth-pam-fido2.so
	rm -f $(DESTDIR)$(PREFIX)/auth-fido2.py

clean:
	rm -f *.so *.o *.gch
