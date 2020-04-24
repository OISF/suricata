SRCS :=		dummy.c

SURICATA_SRC ?=	../..

CPPFLAGS +=	-DSURICATA_PLUGIN -I$(SURICATA_SRC)/src

all:
	gcc -fPIC $(CPPFLAGS) -o libdummy.so -shared $(SRCS)

clean:
	rm -f *.so *~

