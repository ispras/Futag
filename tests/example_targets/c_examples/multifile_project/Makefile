TARGET = multifile.exe
LIBS = 
CC = /home/m4drat/futag-public-package/bin/clang
CFLAGS = -Wall -Iheaders

.PHONY: default all clean

default: $(TARGET)
all: default

OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c))

%.o: %.c
	$(CC) $(CFLAGS) $(EXTRA_C_FLAGS) -c $< -o $@

.PRECIOUS: $(TARGET) $(OBJECTS)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -Wall $(LIBS) -o $@

archive: $(OBJECTS)
	ar rcs multifile_project.a $(OBJECTS)

clean:
	-rm -f *.o
	-rm -f $(TARGET)
	-rm -f multifile_project.a