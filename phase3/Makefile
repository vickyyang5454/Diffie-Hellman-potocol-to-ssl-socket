SRCS	   = ssl_server.c
LIBS	   = -lssl -lcrypto
SERVER_OUT = ssl_server
CLIENT_OUT = ssl_client
CC	   = gcc
CFLAGS	   = -Wall
LIBPATH	   = -L/usr/lib
SERVER_OBJ = ssl_server.o
CLIENT_OBJ = ssl_client.o
COMMON_OBJ = ssl_common.o

%.o: %.c %.h
	$(CC) -c $(CFLAGS) $*.c

all: clean $(SERVER_OUT) $(CLIENT_OUT) clean_obj

$(SERVER_OUT): $(SERVER_OBJ) $(COMMON_OBJ)
	$(CC) $(SERVER_OBJ) $(COMMON_OBJ) $(LIBS) -o $(CLIENT_OUT)

$(CLIENT_OUT): $(CLIENT_OBJ) $(COMMON_OBJ)
	$(CC) $(CLIENT_OBJ) $(COMMON_OBJ) $(LIBS) -o $(CLIENT_OUT)

clean_obj:
	$(RM) $(SERVER_OBJ) $(CLIENT_OBJ) $(COMMON_OBJ)

clean: clean_obj
	$(RM) $(SERVER_OUT) $(CLIENT_OUT)

