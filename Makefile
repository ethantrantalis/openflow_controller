# Compiler and flags
CC = gcc
CFLAGS = -Wall -Werror -g -I./include
LDFLAGS = -pthread

# Target executable
TARGET = controller

# Source directories
SRCDIR = src
INCLUDEDIR = include

# Source files
SRCS = $(SRCDIR)/controller.c \
       $(SRCDIR)/communication.c \
       $(SRCDIR)/checksum.c \
       $(SRCDIR)/smartalloc.c \
       $(SRCDIR)/topology.c

# Object files
OBJS = $(SRCS:.c=.o)

# Header files
HDRS = $(INCLUDEDIR)/controller.h \
       $(INCLUDEDIR)/openflow.h \
       $(INCLUDEDIR)/checksum.h \
       $(INCLUDEDIR)/smartalloc.h \
       $(INCLUDEDIR)/topology.h \
       $(INCLUDEDIR)/communication.h

# Default target
all: $(TARGET)

# Link the executable
$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

# Compile source files
$(SRCDIR)/%.o: $(SRCDIR)/%.c $(HDRS)
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up
clean:
	rm -f $(TARGET) $(SRCDIR)/*.o

.PHONY: all clean