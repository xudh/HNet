CROSS=
CC=$(CROSS)gcc
AR=$(CROSS)ar

INC_DIR := Include
SRC_DIR := Source
LIB_DIR := Library
LIB_TARGET := libNet.a

CFLAGS = -std=gnu99 -O2 -Wall -fno-strict-aliasing
#CFLAGS = -Wno-unused-result 有些版本的gcc要用
CFLAGS += -I$(INC_DIR)

OBJS :=	$(SRC_DIR)/NetInterface		\
		$(SRC_DIR)/NetIConfig		\
		$(SRC_DIR)/Domain			\
		$(SRC_DIR)/TCPUDP			\
		$(SRC_DIR)/DNS				\
		$(SRC_DIR)/Route

OBJS := $(foreach obj, $(OBJS), $(obj).o)
$(SRC_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(LIB_TARGET): $(OBJS)
	$(AR) ruc  $(LIB_TARGET) $(OBJS)
	mv $(LIB_TARGET) $(LIB_DIR)

clean:
	rm -f $(OBJS)
	rm -f $(LIB_DIR)/$(LIB_TARGET)

