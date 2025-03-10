# Compiler and flags
CC = gcc
CFLAGS = -Wall -Werror -g -I/opt/homebrew/Cellar/igraph/0.10.15_1/include/igraph
LDFLAGS = -pthread 

# Target executable
TARGET = controller

# Source files and headers
SRCS = controller.c checksum.c smartalloc.c
HDRS = headers/controller.h headers/openflow. headers/checksum.h headers/smartalloc.h headers/uthash.h

# Object files
OBJS = controller.o checksum.o smartalloc.o

# Default target
all: $(TARGET)

# Link the executable
$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

# Compile source files
%.o: %.c $(HDRS)
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up
clean:
	rm -f $(TARGET) *.o

.PHONY: all clean