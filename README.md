# ttyTLS

This is a command line utility that implements a Transport Layer Security
connection over a UNIX TTY and exports a pseudo-terminal device enabling
secure communication over that TTY. The obvious use-case for this application
is to secure a PPP connection between two machines using a dial-up modem or
serial port, but the program is not restricted to that use-case.

## Usage

`ttyTLS [-l] <tty>`

The `-l` option is for the side of the connection which will listen for
a connection to be established. Once a connection is established, a
PTY will be created on both ends, and the path to that PTY will be output on
stdout. That PTY can be used as you would use the raw TTY, except the data
will be encrypted.
