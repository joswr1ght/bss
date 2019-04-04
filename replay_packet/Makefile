# Bluetooth Stack Smasher (BSS)
# Pierre BETOUIN <pierre.betouin@security-labs.org>

CC=gcc
MAKE=make
CFLAGS=-Wall

BINDIR=/usr/local/bin
ETCDIR=/usr/local/etc

REPLAY_OBJ=replay_l2cap_packet
REPLAY_SRC=replay_l2cap_packet.c
REPLAY_FLAGS=
REPLAY_LIBS=-lbluetooth

all: $(REPLAY_OBJ)

$(REPLAY_OBJ): $(REPLAY_SRC) $(REPLAY_INC)
	$(CC) -o $(REPLAY_OBJ) $(CFLAGS) $(REPLAY_FLAGS) $(REPLAY_SRC) $(REPLAY_LIBS)

install:
	strip $(REPLAY_OBJ)
	cp $(REPLAY_OBJ) $(BINDIR)

clean:
	rm -f $(REPLAY_OBJ)
