#include "port_scan_lib.h"


int main(int argc, char** argv)
{
	unsigned silence_mode = 0;
	unsigned logging_mode = 0;
	FILE* open_ports = 0;
	unsigned int found_ports = 0;
	unsigned int port_start_num = MIN_PORT_NUM;
	unsigned int port_end_num = MAX_PORT_NUM;
	unsigned int time_ms = 10000;
	char* correct_flags_str = NULL;
	char* time_ms_str = NULL;
	char* ip_buf = NULL;
	char* port_buf = NULL;
	fd_set fdset;
	enum work_modes mode;
	struct sockaddr_in addr;
	struct timeval tv;

/* 
 * Проверка корректности переданных аргументов командной строки программе
 * и установка режима работы программы в зависимости от кол-ва параметров
 * */	

	switch ( argc )
	{
		case 2:
			if ( !check_ip_argument(argv[1], &addr, &ip_buf) )
			{
				fprintf(stderr, "Incorrect IP address\n");
				return 1;
			}
			mode = IP_ONLY;
			break;
		case 3:
			if ( argv[1][0] == '-' )
			{  
				if ( !check_ip_argument(argv[2], &addr, &ip_buf) )
				{
					fprintf(stderr, "Incorrect IP address\n");
					return 1;
				}

				if ( !check_params_argument(argv[1], &time_ms_str, &correct_flags_str, &time_ms) )
				{
					fprintf(stderr, "%s\n", "Incorrect flags usage!\nRight flags: -slt=<value_in_ms>");
					if ( correct_flags_str )
						free(correct_flags_str);
					if ( ip_buf )
						free(ip_buf);
					return 1;
				}
				mode = IP_FLAGS;
			}
			else if ( (argv[1][0] >= '0') && (argv[1][0] <= '9') )
			{
				if ( !check_ip_argument(argv[1], &addr, &ip_buf) )
				{
					fprintf(stderr, "Incorrect IP address\n");
					return 1;
				}
					
				check_port_argument(argv[2], &port_buf, &port_start_num, &port_end_num);
				mode = IP_PORT;
			}
			else
			{
				fprintf(stderr, "Incorrect IP address\n");
				return 1;
			}
			break;
		case 4:
			if ( !check_ip_argument(argv[2], &addr, &ip_buf) )
			{
				fprintf(stderr, "Incorrect IP address\n");
				return 1;
			}

			if ( !check_params_argument(argv[1], &time_ms_str, &correct_flags_str, &time_ms) )
			{
				fprintf(stderr, "%s\n", "Incorrect usage!\nTry: <program_name> [-slt=<ms>] <ip_addr> [\"min_port-max_port\"/\"port_num\"]");
				if ( correct_flags_str )
					free(correct_flags_str);
				if ( ip_buf )
					free(ip_buf);
				return 1;
			}

			check_port_argument(argv[3], &port_buf, &port_start_num, &port_end_num);
			mode = IP_FLAGS_PORT;
			break;
		default:
			fprintf(stderr, "%s\n", "Incorrect usage!\nTry: <program_name> [-slt=<ms>] <ip_addr> [\"min_port-max_port\"/\"port_num\"]");
			return 1;
	}

/*///////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////)*/
/*Назначение конфигурационных параметров в зависимости от выбранного режима работы*/

	if ( mode == IP_ONLY )
	{
		silence_mode = 0;
		logging_mode = 0;
		tv.tv_sec = 10;
		tv.tv_usec = 0;

		port_start_num = MIN_PORT_NUM;
		port_end_num = MAX_PORT_NUM;
	}
	else if ( mode == IP_FLAGS ) 
	{
		/*s=1|l=1|t=10000 2,6*/
		silence_mode = correct_flags_str[2] - '0';
		logging_mode = correct_flags_str[6] - '0';
		/*free(correct_flags_str);*/
		if ( time_ms > 10000 )
			time_ms = 10000;
		tv.tv_sec = time_ms / 1000;
		unsigned int buf_time = time_ms % 1000; 
		tv.tv_usec = buf_time*1000;

		port_start_num = MIN_PORT_NUM;
		port_end_num = MAX_PORT_NUM;
	}
	else if ( mode == IP_PORT )
	{
		silence_mode = 0;
		logging_mode = 0;
		tv.tv_sec = 10;
		tv.tv_usec = 0;
	}
	else if ( mode == IP_FLAGS_PORT )
	{
		silence_mode = correct_flags_str[2] - '0';
		logging_mode = correct_flags_str[6] - '0';
		/*free(correct_flags_str);*/
		if ( time_ms > 10000 )
			time_ms = 10000;
		tv.tv_sec = time_ms / 1000;
		unsigned int buf_time = time_ms % 1000; 
		tv.tv_usec = buf_time*1000;
	}

	/*printf("<<<<<<<<<<<======== DEBUG MODE ========>>>>>>>>>>>\n"
		   "Flag \"s\" = %u\n"
		   "Flag \"l\" = %u\n"
		   "correct_flags_str = %s\n"
		   "time_ms = %u\n"
		   "tv.tv_sec = %u\n"
		   "tv.tv_usec = %u\n"
		   "mode = %u\n"
		   "port_start_num = %u\n"
		   "port_end_num = %u\n"
		   "<<<<<<<<<<<======== DEBUG MODE ========>>>>>>>>>>>\n", 
		   silence_mode, 
		   logging_mode, 
		   correct_flags_str, 
		   time_ms, 
		   (unsigned int)tv.tv_sec, 
		   (unsigned int)tv.tv_usec, 
		   mode, 
		   port_start_num, 
		   port_end_num);
	*/

	if (correct_flags_str)
		free(correct_flags_str);

/*///////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////)*/

	if ( logging_mode )
	{
		char filename[100];
		get_log_filename(filename);
		if ( !(open_ports = fopen(filename, "w")) )
		{
			if ( !silence_mode )
				fprintf(stderr, "[%s] [WARN]: Unable to create log file \"%s\"\n"
								"[%s] [INFO]: Check your directories permissions on creating files\n"
								"[%s] [INFO]: Logging mode turning off..\n", get_curtime_as_string(), filename, get_curtime_as_string(), get_curtime_as_string());
			logging_mode = 0;
		}
	}
	
	conf_settings* cfgsets = NULL;
	cfgsets = malloc(sizeof(conf_settings));
	if ( cfgsets )
	{
		cfgsets->silence_mode = silence_mode ? "ON" : "OFF";
		cfgsets->logging_mode = logging_mode ? "ON" : "OFF";
		cfgsets->time_ms = time_ms;
		cfgsets->time_sec = (unsigned int)tv.tv_sec;
		cfgsets->time_usec = (unsigned int)tv.tv_usec;
		cfgsets->mode = mode;
	}
	
	wait_mes_params* wm_params = NULL;
	wm_params = malloc(sizeof(wait_mes_params));
	if ( wm_params )
	{
		wm_params->port_start_num = port_start_num;
		wm_params->port_end_num = port_end_num;
		wm_params->ip_buf = ip_buf;
	}

	if ( !silence_mode )
	{
		show_conf_settings(stdout, cfgsets);
		show_wait_message(stdout, wm_params);
	}
	if ( logging_mode )
	{
		show_conf_settings(open_ports, cfgsets);
		show_wait_message(open_ports, wm_params);
	}

	if ( cfgsets )
		free(cfgsets);
	
	if ( wm_params )
		free(wm_params);

	if ( port_start_num > port_end_num )
		port_end_num = MAX_PORT_NUM;

	int port_num = port_start_num;

	time_t work_timer_start = time(0); /*timer_start*/

	for ( ; port_num <= port_end_num; port_num++ )
	{
		int peer_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (peer_sock == -1)
		{	
			if ( open_ports )
				fclose(open_ports);
			if ( ip_buf )
				free(ip_buf);

			if ( !silence_mode )
				fprintf(stderr, "[%s] [ERROR]: socket() failed. {%d}\n", get_curtime_as_string(), errno);
			if ( logging_mode )
				fprintf(open_ports, "[%s] [ERROR]: socket() failed. {%d}\n", get_curtime_as_string(), errno);

			return 1;
		}
		fcntl(peer_sock, F_SETFL, O_NONBLOCK);
		addr.sin_port = htons(port_num);

		FD_ZERO(&fdset);
		FD_SET(peer_sock, &fdset);
		
		int ret_val = connect(peer_sock, (struct sockaddr*) &addr, sizeof(addr));
		/*if ( ret_val == -1 )
		{
			if ( open_ports )
				fclose(open_ports);
			if ( ip_buf )
				free(ip_buf);

			if ( !silence_mode )
				fprintf(stderr, "[%s] [ERROR]: connect() failed. {%d}\n", get_curtime_as_string(), errno);
			if ( logging_mode )
				fprintf(open_ports, "[%s] [ERROR]: connect() failed. {%d}\n", get_curtime_as_string(), errno);

			return 1;
		}*/

		if ( select(peer_sock+1, NULL, &fdset, NULL, &tv) == 1 )
		{
			int so_error;
			socklen_t len = sizeof(so_error);
			getsockopt(peer_sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
			if ( so_error == 0 )
			{
				found_ports++;
				if ( !silence_mode )
					printf("[%s] [INFO]: Port %5u is OPEN          [%s]\n", get_curtime_as_string(), port_num, ip_buf);
				if ( logging_mode )
					fprintf(open_ports, "[%s] [INFO]: Port %5u is OPEN          [%s]\n", get_curtime_as_string(), port_num, ip_buf);
			}
		}
		close(peer_sock);
	}
	time_t work_timer_stop = time(0); /*timer finish*/
	time_t work_time = work_timer_stop-work_timer_start;
	
	success_params* success_args = NULL;
	success_args = malloc(sizeof(success_params));
	if ( success_args )
	{
		success_args->work_time = (unsigned long long)work_time;
		success_args->ip_buf = ip_buf;
		success_args->found_ports = found_ports;
	}

	if ( !silence_mode )
		show_success_message(stdout, success_args);

	if ( logging_mode )
		show_success_message(open_ports, success_args);

	if ( success_args )
		free(success_args);

	if ( open_ports )
		fclose(open_ports);

	if (ip_buf)
		free(ip_buf);

	return 0;
}
