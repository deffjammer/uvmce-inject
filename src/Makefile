INC_DIR=../include
CFLAGS=-g -I$(INC_DIR)
LDFLAGS=-lnuma
SRCS_2 = common.c migrate_pages.c 
SRCS_1 = uncorrected_memory_error.c common.c  
SRCS = common.c patrol_scrub_mce.c 
OBJS_2 = $(SRCS_2:.c=.o)
OBJS_1 = $(SRCS_1:.c=.o)
OBJS = $(SRCS:.c=.o)
UCE   = uce
PSUCE = ps_uce
MGPS  = migrate_pages 

all: 
	$(CC) $(CFLAGS) $(SRCS_2)  $(LDFLAGS) -o $(MGPS)
	$(CC) $(CFLAGS) $(SRCS_1)  $(LDFLAGS) -o $(UCE)
	$(CC) $(CFLAGS) $(SRCS)  $(LDFLAGS) -o $(PSUCE)

clean:
	rm -f $(OBJS_1) $(UCE)
	rm -f $(OBJS) $(PSUCE)

