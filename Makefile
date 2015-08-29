TARGET: main
CC = gcc
CFLAGS = -Wall


dir:
	mkdir -p obj
	mkdir -p obj/mdns
	mkdir -p obj/mdns/msg
	mkdir -p obj/tests
	mkdir -p obj/tests/mdns

mdns_msg_header: dir ./mdns/msg/header.c ./mdns/msg/header.h \
	               ./mdns/msg/limits.h
	$(CC) $(CFLAGS) ./mdns/msg/header.c -c -o obj/mdns/msg/header.o

mdns_msg_question: dir ./mdns/msg/question.h ./mdns/msg/question.c \
	                 ./mdns/msg/limits.h
	$(CC) $(CFLAGS) ./mdns/msg/question.c -c -o obj/mdns/msg/question.o

mdns_msg_resource: dir ./mdns/msg/resource.c ./mdns/msg/resource.h \
	                 ./mdns/msg/limits.h
	$(CC) $(CFLAGS) ./mdns/msg/resource.c -c -o obj/mdns/msg/resource.o

mdns_msg: mdns_msg_resource mdns_msg_question mdns_msg_header \
	        ./mdns/msg/msg.c ./mdns/msg/msg.h
	$(CC) $(CFLAGS) ./mdns/msg/msg.c -c -o obj/mdns/msg/msg.o

mdns: mdns_msg ./mdns/mdns.c ./mdns/mdns.h
	$(CC) $(CFLAGS) ./mdns/mdns.c -c -o obj/mdns/mdns.o

tests_mdns_msg: dir ./tests/mdns/msg.h ./tests/mdns/msg.c mdns_msg_header \
	              mdns_msg_question
	$(CC) $(CFLAGS) ./tests/mdns/msg.c -c -o obj/tests/mdns/msg.o

tests_mdns: dir tests_mdns_msg ./tests/mdns/mdns.h ./tests/mdns/mdns.c
	$(CC) $(CFLAGS) ./tests/mdns/mdns.c -c -o obj/tests/mdns/mdns.o

tests: dir tests_mdns ./tests/tests.c ./tests/tests.h
	$(CC) $(CFLAGS) ./tests/tests.c -c -o obj/tests/tests.o

main: mdns tests main.c
	$(CC) $(CFLAGS) main.c \
	 obj/mdns/msg/header.o obj/mdns/msg/question.o obj/mdns/msg/resource.o \
	 obj/mdns/msg/msg.o obj/mdns/mdns.o \
	 obj/tests/tests.o obj/tests/mdns/msg.o obj/tests/mdns/mdns.o \
	 -o cos

clean:
	rm -rf obj
	rm *.gch */*.gch */*/*.gch */*/*/*.gch */*/*/*/*.gch
