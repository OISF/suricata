NAME :=		source-pfring

SRCS :=		plugin.c \
		source-pfring.c \
		runmode-pfring.c

CPPFLAGS +=	-DHAVE_PF_RING_FLOW_OFFLOAD
CPPFLAGS +=	-DSURICATA_PLUGIN -I. 

# Specify the path to the Suricata source code.
CPPFLAGS +=	-I../../../src

all:
	gcc -fPIC $(CPPFLAGS) -o $(NAME).so -shared $(SRCS)

clean:
	rm -f *.so *~
