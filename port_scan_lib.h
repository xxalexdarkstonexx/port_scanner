#ifndef PORT_SCANNER_H_SENTRY
#define PORT_SCANNER_H_SENTRY

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

enum {
		MAX_LEN_VALID_FLAGS = 9,
		MIN_VALID_ARGS_NUM = 2,
		MAX_VALID_ARGS_NUM = 4,
		MIN_PORT_NUM = 1,
		MAX_PORT_NUM = 65535
	 };

enum work_modes {
					IP_ONLY = 1,
					IP_FLAGS,
					IP_PORT,
					IP_FLAGS_PORT
				};

typedef struct
{
	char* silence_mode;
	char* logging_mode;
	unsigned int time_ms;
	unsigned int time_sec; 
	unsigned int time_usec;
	unsigned int mode;
} conf_settings;

typedef struct
{
	unsigned long long work_time;
	unsigned int found_ports;
	char* ip_buf;
} success_params;

typedef struct
{
	unsigned int port_start_num;
	unsigned int port_end_num;
	char* ip_buf;
} wait_mes_params;

void show_conf_settings(FILE* stream, conf_settings* cfgsets);
void show_wait_message(FILE* stream, wait_mes_params* wm_params);
void show_success_message(FILE* stream, success_params* args);
unsigned int get_month_number(const char* month);
char* get_log_filename(char* filename_buf);
char* get_curtime_as_string(void);
int check_ip_argument(const char* ip, struct sockaddr_in* addr, char** ip_buf);
int check_params_argument(const char* params_str, char** time_ms_str, char** correct_flags_str, unsigned int* time_ms);
void check_port_argument(const char* port, char** port_buf, unsigned int* port_start_num, unsigned int* port_end_num);

#ifdef PORT_SCANNER_C
#include "port_scan_lib.c"
#endif

#endif
