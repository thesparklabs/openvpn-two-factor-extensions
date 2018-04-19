PREFIX=/etc/openvpn
CFLAGS += -DPREFIX='"$(PREFIX)"' -DUSE_PAM_DLOPEN=1

OBJS = auth-pam-u2f.o pamdl.o utils.o

all: auth-pam-u2f.so

auth-pam-u2f.o: auth-pam-u2f.c
	$(CC) $(CFLAGS) -fPIC -c auth-pam-u2f.c utils.c pamdl.c pamdl.h

auth-pam-u2f.so: auth-pam-u2f.o pamdl.o utils.o
	$(CC) -fPIC -shared -o auth-pam-u2f.so $(OBJS)

install: auth-pam-u2f.so
	mkdir -p $(DESTDIR)$(PREFIX)
	install -c auth-pam-u2f.so -m 755 $(DESTDIR)$(PREFIX)
	install -c auth-pam-u2f.py -m 755 $(DESTDIR)$(PREFIX)

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/auth-pam-u2f.so
	rm -f $(DESTDIR)$(PREFIX)/auth-pam-u2f.py

clean:
	rm -f *.so *.o *.gch