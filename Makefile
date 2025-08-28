CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2

# Detect operating system
UNAME_S := $(shell uname -s)

# SSH library flags (Linux/macOS)
SSH_CFLAGS = $(shell pkg-config --cflags libssh2 2>/dev/null)
SSH_LIBS = $(shell pkg-config --libs libssh2 2>/dev/null)

# Windows specific settings
ifeq ($(OS),Windows_NT)
    # Windows with MinGW
    SSH_CFLAGS = -I/mingw64/include
    SSH_LIBS = -L/mingw64/lib -lssh2 -lws2_32
    EXT = .exe
else
    EXT =
endif

all: server$(EXT) client$(EXT)

server$(EXT): server.c delete_directory.c delete_directory.h
	$(CC) $(CFLAGS) -o server$(EXT) server.c delete_directory.c

client$(EXT): client.c delete_directory.c delete_directory.h
	@echo "Compiling SSH client..."
	@if [ -z "$(SSH_LIBS)" ]; then \
		echo "ERROR: libssh2 not found. Please install it first:"; \
		echo "  Ubuntu/Debian: sudo apt-get install libssh2-1-dev"; \
		echo "  CentOS/RHEL:   sudo yum install libssh2-devel"; \
		echo "  macOS:         brew install libssh2"; \
		echo "  Windows:       Install MSYS2 and: pacman -S mingw-w64-x86_64-libssh2"; \
		exit 1; \
	fi
	$(CC) $(CFLAGS) $(SSH_CFLAGS) -o client$(EXT) client.c delete_directory.c $(SSH_LIBS)

install-deps:
	@echo "Installing libssh2 development library..."
	@echo "Choose your system:"
	@echo ""
	@echo "Ubuntu/Debian:"
	@echo "  sudo apt-get update"
	@echo "  sudo apt-get install libssh2-1-dev"
	@echo ""
	@echo "CentOS/RHEL/Fedora:"
	@echo "  sudo yum install libssh2-devel"
	@echo "  # or for newer systems:"
	@echo "  sudo dnf install libssh2-devel"
	@echo ""
	@echo "macOS:"
	@echo "  brew install libssh2"
	@echo ""
	@echo "Windows (MSYS2):"
	@echo "  pacman -S mingw-w64-x86_64-libssh2"

test-ssh:
	@echo "Testing SSH connection..."
	@echo "Try connecting manually first:"
	@echo "  ssh ege@192.168.0.172"
	@echo ""
	@echo "If that works, your SSH client should work too!"

run-server: server$(EXT)
	@echo "Starting server on port 5000..."
	./server$(EXT)

run-client: client$(EXT)
	@echo "Starting SSH client..."
	./client$(EXT)

clean:
	rm -f server$(EXT) client$(EXT)

help:
	@echo "Available targets:"
	@echo "  all          - Build both server and client"
	@echo "  server       - Build server only"
	@echo "  client       - Build client only (requires libssh2)"
	@echo "  install-deps - Show how to install dependencies"
	@echo "  test-ssh     - Show how to test SSH connection"
	@echo "  run-server   - Build and run server"
	@echo "  run-client   - Build and run client"
	@echo "  clean        - Remove built files"
	@echo "  help         - Show this help"

.PHONY: all clean install-deps test-ssh run-server run-client help