A TinyDTLS fork whose sole purpose is stateful fuzzing of TinyDTLS. 
The fuzzing framework was implemented largely by Ahmed Dawood.

# Overview
The main component of the framework is the *harness*, dtls-fuzz.c, located in the 'tests' directory.
It maintains a client and a server TinyDTLS instance in order to:
1. generate DTLS messages for a given *handshake*, where the handshake is determined by the key exchange algorithm used (**psk** for pre-shared key, **ecc** for eliptic curve diffie-hellman)
2. execute all DTLS messages of the handshake, on the client/server instances
3. replace a DTLS message in a sequence by a a different one, read from a file (useful for fuzzing) 

For the remainder of this README, we assume that commands are run from within the 'tests' directory.
Note that by DTLS message we refer to the actual DTLS record that is sent over UDP.
This record may encapsulate a DTLS handshake message.

# Quickrun

We begin by cleaning/compiling the sources.

> LOG_LEVEL_DTLS=LOG_LEVEL_DBG make clean all

By setting LOG_LEVEL_DTLS to LOG_LEVEL_DBG we print out all logging data. 
We then generate handshake messages for a PSK handshake.

> ./dtls-fuzz psk

The directories 'handshakes' and 'handshakes/psk' should have been created, with the latter containing files '0', '1'... .
Each such file contains the contents of a DTLS message sent during execution, with the name suggesting the index the message in the handshake sequence.
The extensive print-out should include two "Handshake complete" logs, suggesting that both sides were able to complete the handshake.
This is because the handshake is actually executed as the messages are generated.
To visualize the raw messages generated you can use a hex viewer/editor (e.g. xxd, hexdump, hexedit).
Alternatiively, you can transform them to pcap to view them on wireshark. we also include an adaptation of Hanno Böck

We finally (re-)execute the handshake, replacing the fifth message (ClientKeyExchange) by the first (ClientHello):

> ./dtls-fuzz handshakes/psk/0 psk 5

If you check the logs again, you should find that only one of the sides is able to complete a handshake. 
The side that is not is the server, since it has not received the ClientKeyExchange message as expected.

# Usage

## Message generation
The harness can automatically generate messages for PSK and ECC (with certificate required)  handshake. For that, you just run:

> ./dtls-fuzz psk/ecc

The harness will execute the correspond handshake while at the same time dumping the bytes the SUT generates to files named 0, 1, 2... .
These files are stored in 'handshakes', in a folder corresponding to the key exchange algorithm used ('psk' or 'ecc').

### Message visualization
To visualize the messages generated you can use a hex viewer/editor (e.g. xxd, hexdump, hexedit).
Alternatively, you can transform them to .pcap to view them on wireshark.
The latter can be done using the 'raw2udppcap.sh' script found in 'scripts' directory.

## Message execution with replacement
Once messages for a handshake have been generated, the harness can re-execute them.
Therein, it replaces one message (suggested by its index in the handshake) by another provided in a user-supplied file.
This is useful for fuzzing from that point in the handshake.

The first bellow command simply replays the handshake (it replaces message at index 0 (ClientHello) by the same message).
The second command executes a modified handshake in which the first ClientHello (index 0) is replaced by the second (index 2).

> ./dtls-fuzz handshakes/psk/2 psk 0

The three arguments can be joined using ',' into a single argument, exercising the same functionality.
> ./dtls-fuzz handshakes/psk/2,psk,0

This can be useful when dealing with tools which do not support execution of the harness using more than one argument.


# Old TinyDTLS README
CONTENTS

This library contains functions and structures that can help
constructing a single-threaded UDP server with DTLS support in
C99. The following components are available:

* dtls
  Basic support for DTLS with pre-shared key mode.

* tests
  The subdirectory tests contains test programs that show how each
  component is used.

BUILDING

When using the code from the git repository, invoke make to build DTLS as a
shared library.
