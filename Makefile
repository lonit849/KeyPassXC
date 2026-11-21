# KeyPassXC - Makefile
CC = gcc
CFLAGS = -Wall -Wextra -O2
LIBS = -lcrypto -lpthread -lm
TARGET = keypass
SRC = keypass.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LIBS)
	@echo "✅ Built: ./keypass"
	@echo "Run: ./keypass"

clean:
	rm -f $(TARGET) vault.dat vault.dat.bak
	@echo "Cleaned"

install-deps:
	@echo "Installing dependencies..."
	@which apt && sudo apt update && sudo apt install -y libssl-dev xclip || true
	@which pkg && pkg install -y openssl termux-api || true
	@which brew && brew install openssl || true

backup:
	@echo "Backing up vault..."
	@cp -f vault.dat vault.dat.bak 2>/dev/null || echo "No vault yet"
	@mkdir -p ~/.keypass_backup ~/KeyPassBackup
	@cp -f vault.dat ~/.keypass_backup/vault.dat.hidden 2>/dev/null || true
	@cp -f vault.dat ~/KeyPassBackup/vault.dat 2>/dev/null || true
	@echo "✅ Backed up to 3 locations"

check:
	@echo "Checking vault integrity..."
	@ls -lh vault.dat vault.dat.bak ~/.keypass_backup/vault.dat.hidden 2>&1

help:
	@echo "make         - Build keypass"
	@echo "make clean   - Remove binary + vault"
	@echo "make backup  - Manual backup"
	@echo "make check   - Check backup files"
	@echo "make install-deps - Install OpenSSL + xclip"

.PHONY: all clean install-deps backup check help
