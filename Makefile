CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c11

SRC_DIR = src
BIN_DIR = bin

CLIENT = $(BIN_DIR)/client
SERVER = $(BIN_DIR)/server

CLIENT_SRC = $(SRC_DIR)/main_client.c $(SRC_DIR)/udp.c $(SRC_DIR)/packet.c
SERVER_SRC = $(SRC_DIR)/main_server.c $(SRC_DIR)/udp.c $(SRC_DIR)/packet.c

.PHONY: all clean

all: $(CLIENT) $(SERVER)

$(CLIENT): $(CLIENT_SRC)
	mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^

$(SERVER): $(SERVER_SRC)
	mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -rf $(BIN_DIR)
