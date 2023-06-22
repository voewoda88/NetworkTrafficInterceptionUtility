CC = gcc

SRC = main.c

client: $(SRC)
	$(CC) $(CFLAGS) -o $@ $^

.PHONY: run
run:
	make main
	./main
	make clean

.PHONY: clean
clean:
	rm main
