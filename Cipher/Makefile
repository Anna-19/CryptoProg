# Компилятор
CC = g++

# Флаги компиляции
CFLAGS = -Wall -Wextra -std=c++14

# Имя исполняемого файла
EXEC = hash

# Библиотеки для связывания
LDLIBS = -lcrypto++

# Исходные файлы
SRCS = AES.cpp main.cpp

# Объектные файлы
OBJS = $(SRCS:.cpp=.o)

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(EXEC)
