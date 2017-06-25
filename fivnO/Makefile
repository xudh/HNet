CROSS=
CC=$(CROSS)gcc
AR=$(CROSS)ar

INC_DIR := Include
SRC_DIR := Source
LIB_DIR := Library
LIB_TARGET := libOnvif.a

CFLAGS = -std=gnu99 -O2 -Wall -fno-strict-aliasing
#CFLAGS = -Wno-unused-result 有些版本的gcc要用
#CFLAGS += -DWITH_NOIDREF 可能减小体积
CFLAGS += -I$(INC_DIR)

OBJS :=	$(SRC_DIR)/OnvifClient	\
		$(SRC_DIR)/OnvifServer	\
		$(SRC_DIR)/soapClient	\
		$(SRC_DIR)/soapServer	\
		$(SRC_DIR)/soapC		\
		$(SRC_DIR)/stdsoap2		\
		$(SRC_DIR)/duration		\
		$(SRC_DIR)/Base64		\
		$(SRC_DIR)/SHA1

OBJS := $(foreach obj, $(OBJS), $(obj).o)
$(SRC_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(LIB_TARGET): $(OBJS)
	$(AR) ruc  $(LIB_TARGET) $(OBJS)
	mv $(LIB_TARGET) $(LIB_DIR)

clean:
	rm -f $(OBJS)
	rm -f $(LIB_TARGET)

