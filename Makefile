# Compiler and flags
CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -pthread

# Target executable
TARGET = controller

# Source files and headers
SRCS = controller.c
HDRS = controller.h openflow.h

# Default target
all: $(TARGET)

# Link the executable
$(TARGET): controller.o
	$(CC) controller.o -o $(TARGET) $(LDFLAGS)

# Compile source files
controller.o: $(SRCS) $(HDRS)
	$(CC) $(CFLAGS) -c $(SRCS)

# Clean up
clean:
	rm -f $(TARGET) *.o

.PHONY: all clean