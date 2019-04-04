# Bluetooth Stack Smasher (BSS)
# Pierre BETOUIN <pierre.betouin@security-labs.org>

CC=gcc
MAKE=make
CFLAGS=-Wall

BINDIR=/usr/local/bin
ETCDIR=/usr/local/etc

BSS_OBJ=bss
BSS_SRC=bss.c
BSS_FLAGS=
BSS_LIBS=-lbluetooth

all: $(BSS_OBJ)

$(BSS_OBJ): $(BSS_SRC) $(BSS_INC)
	$(CC) -o $(BSS_OBJ) $(CFLAGS) $(BSS_FLAGS) $(BSS_SRC) $(BSS_LIBS)

install:
	strip $(BSS_OBJ)
	cp $(BSS_OBJ) $(BINDIR)

clean:
	rm -f $(BSS_OBJ)
	rm -f replay_packet/replay_l2cap_packet 
