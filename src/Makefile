INC_DIR=../include
CFLAGS=-g -I$(INC_DIR)
#LDFLAGS=-lnuma
LDFLAGS=/usr/lib64/libnuma.so.1
SRCS   = error_inject_tool.c common.c  
SRCS_1 = common.c migrate_pages.c 
OBJS   = $(SRCS:.c=.o)
OBJS_1 = $(SRCS_1:.c=.o)
EIJ   = einj_tool
MGPS  = migrate_pages 

all: 
	$(CC) $(CFLAGS) $(SRCS)    $(LDFLAGS) -o $(EIJ)
	$(CC) $(CFLAGS) $(SRCS_1)  $(LDFLAGS) -o $(MGPS)

clean:
	rm -f $(OBJS) $(EIJ)
	rm -f $(OBJS_1) $(MGPS)

