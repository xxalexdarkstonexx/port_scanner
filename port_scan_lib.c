#ifndef PORT_SCANNER_C_SENTRY
#define PORT_SCANNER_C_SENTRY

#include "port_scan_lib.h"

void show_conf_settings(FILE *stream, conf_settings* cfgsets)
{
	fprintf(stream, "[%s] [INFO]: Configuration settings:\n"
					"[%s] [INFO]: Silence mode: %s\n"
					"[%s] [INFO]: Logging mode: %s\n"
					"[%s] [INFO]: Select() delay:\n"
					"[%s] [INFO]: time_ms = %u\n"
					"[%s] [INFO]: tv.tv_sec = %u\n"
					"[%s] [INFO]: tv.tv_usec = %u\n"
					"[%s] [INFO]: mode = %u\n\n",
					get_curtime_as_string(), 
					get_curtime_as_string(), (cfgsets != NULL) ? cfgsets->silence_mode : "Not stated",
					get_curtime_as_string(), (cfgsets != NULL) ? cfgsets->logging_mode : "Not stated",
					get_curtime_as_string(), 
					get_curtime_as_string(), (cfgsets != NULL) ? cfgsets->time_ms : (unsigned int)10000, 
					get_curtime_as_string(), (cfgsets != NULL) ? cfgsets->time_sec : (unsigned int)10, 
					get_curtime_as_string(), (cfgsets != NULL) ? cfgsets->time_usec : (unsigned int)0, 
					get_curtime_as_string(), (cfgsets != NULL) ? cfgsets->mode : (unsigned int)1
			);
}
void show_wait_message(FILE *stream, wait_mes_params* wm_params)
{
	unsigned int port_start_num;
	unsigned int port_end_num;


	if ( wm_params )
	{
		port_start_num = wm_params->port_start_num;
		port_end_num = wm_params->port_end_num;
	}
	else
	{
		port_start_num = MIN_PORT_NUM;
		port_end_num = MAX_PORT_NUM;
	}

	if (port_start_num == port_end_num )
		fprintf(stream, "[%s] [INFO]: Scanning port number %u [%s]\n"
						"[%s] [INFO]: Please wait...\n"
						"---------------------------------------------------------------\n", 
						get_curtime_as_string(), port_start_num, (wm_params != NULL) ? wm_params->ip_buf : "Not stated", 
						get_curtime_as_string()
			   );
	else
		fprintf(stream, "[%s] [INFO]: Scanning ports from %u to %u [%s]\n"
						"[%s] [INFO]: Please wait...\n"
						"---------------------------------------------------------------\n", 
						get_curtime_as_string(), port_start_num, port_end_num, (wm_params != NULL) ? wm_params->ip_buf : "Not stated", 
						get_curtime_as_string()
			   );
}
void show_success_message(FILE *stream, success_params* args)
{
	fprintf(stream, "---------------------------------------------------------------\n"
				    "[%s] [INFO]: Process has been successfully finished for %llds\n"
		            "[%s] [INFO]: Found %d opened ports on %s host\n", 
					get_curtime_as_string(), 
					( args != NULL ) ? args->work_time : (long long)-1, 
					get_curtime_as_string(), 
					( args != NULL ) ? args->found_ports : -1, 
					( args != NULL ) ? args->ip_buf : "Not stated"
		   );
}
unsigned int get_month_number(const char* month)
{
	const char* months[] = {
									"Jan",
									"Feb",
									"Mar",
									"Apr",
									"May",
									"Jun",
									"Jul",
									"Aug",
									"Sep",
									"Oct",
									"Nov",
									"Dec",
									NULL
						   };

	unsigned int i = 0;
	for ( ; months[i]; i++ )
		if ( strcmp(month, months[i]) == 0 )
			return (i+1);
	return 0;
}
char* get_log_filename(char* filename_buf)
{
	const char* suffix = "log.txt";
	char* time_tokens[5];
	int month_num;
	char* month;


	time_t current_time = time(0);
	char* buf = ctime(&current_time);

	char* istr = strtok(buf, " ");
	int k = 0;
	while (istr)
	{
		time_tokens[k] = istr;
		k++;
		istr = strtok(NULL, " ");
	}
	
	month_num = get_month_number(time_tokens[1]);
	switch (month_num)
	{
		case 1:
			month = "01";
			break;
		case 2:
			month = "02";
			break;
		case 3:
			month = "03";
			break;
		case 4:
			month = "04";
			break;
		case 5:
			month = "05";
			break;
		case 6:
			month = "06";
			break;
		case 7:
			month = "07";
			break;
		case 8:
			month = "08";
			break;
		case 9:
			month = "09";
			break;
		case 10:
			;month = "10";
			break;
		case 11:
			month = "11";
			break;
		case 12:
			month = "12";
			break;
		default:
			month = "00";
	}

	for ( k = 0; time_tokens[2][k]; k++ )
		filename_buf[k] = time_tokens[2][k];
	filename_buf[k] = '_';
	k++;
	int cur_pos = k;
	
	for ( k = 0; month[k]; k++, cur_pos++ )
		filename_buf[cur_pos] = month[k];
	filename_buf[cur_pos] = '_';
	cur_pos++;

	for ( k = 0; time_tokens[4][k] != '\n'; k++, cur_pos++ )
		filename_buf[cur_pos] = time_tokens[4][k];
	filename_buf[cur_pos] = '_';
	cur_pos++;

	for ( k = 0; time_tokens[3][k]; k++, cur_pos++ )
	{
		if (time_tokens[3][k] == ':')
			filename_buf[cur_pos] = '_';
		else
			filename_buf[cur_pos] = time_tokens[3][k];
	}
	filename_buf[cur_pos] = '_';
	cur_pos++;
	
	for ( k = 0; suffix[k]; k++, cur_pos++ )
		filename_buf[cur_pos] = suffix[k];
	filename_buf[cur_pos] = '\0';

	return filename_buf;
}
char* get_curtime_as_string(void)
{
	char* time_tokens[5];
	time_t current_time = time(0);
	char* buf = ctime(&current_time);

	char* istr = strtok(buf, " ");
	int k = 0;
	while (istr)
	{
		time_tokens[k] = istr;
		k++;
		istr = strtok(NULL, " ");
	}

	return time_tokens[3];
}
int check_ip_argument(const char* ip, struct sockaddr_in* addr, char** ip_buf)
{
	int ip_len = strlen(ip);
	*ip_buf = malloc(sizeof(char)*ip_len + 1);
	
	if ( !(*ip_buf) )
	{
		fprintf(stderr, "[%s] [ERROR]: Unable to malloc() memory for \"ip_buf\"\n", get_curtime_as_string());
		return 0;
	}

	int i;
	for ( i = 0; i < ip_len; i++ )
		(*ip_buf)[i] = ip[i];
	(*ip_buf)[i] = '\0';
				
	(*addr).sin_family = AF_INET;
	int ok = inet_aton(*ip_buf, &((*addr).sin_addr));

	if ( !ok )
	{
		if ( *ip_buf )
			free(*ip_buf);
		return 0;
	}

	return 1;
}
static char* make_cor_flags_str(unsigned int flag_sum, const char* templ_flags, unsigned int t_flag_len, char* time_ms_str)
{
	char* correct_flags_str = NULL;
	int i;

	if ( (flag_sum % 2) == 1 )
	{
		int str_flag_size = 10;
		str_flag_size += t_flag_len;
		correct_flags_str = malloc(sizeof(char) * str_flag_size + 1);
		if ( !correct_flags_str )
			return NULL;
		int k = 0;
		for ( i = 0; i < str_flag_size; i++ )
		{
			if ( i < 10 )
				correct_flags_str[i] = templ_flags[i];
			else
			{
				correct_flags_str[i] = time_ms_str[k];
				k++;
			}
		}
	}
	else
	{
		int str_flag_size = 15;
		correct_flags_str = malloc(sizeof(char) * str_flag_size + 1);
		if ( !correct_flags_str )
			return NULL;
		for (i = 0; templ_flags[i]; i++)
			correct_flags_str[i] = templ_flags[i];
	}
	correct_flags_str[i] = '\0';

	return correct_flags_str;
}
int str_to_int(const char* str, unsigned int int_len, unsigned int start_index)
{
	int result_int = 0;
	int j, k;
	for (j=start_index, k=int_len; k > 0; j++, k--)
	{
		int d = (str[j] - '0');
		int z;
		for (z=1; z <= (k-1); z++)
			d *= 10;
		result_int += d;
	}
	
	return result_int;
}
int check_params_argument(const char* params_str, char** time_ms_str, char** correct_flags_str, unsigned int* time_ms )
{
	unsigned int correct_flags = 0;
	unsigned int t_flag_len = 0;
	unsigned int s_flag = 0, l_flag = 0, t_flag = 0;


	int i;
	for ( i = 1; params_str[i] && (i <= MAX_LEN_VALID_FLAGS); i++ )
	{
		if ( params_str[i] == 's' )
		{
			if (s_flag) continue;
			s_flag = 4;
			correct_flags++;
			continue;
		}
		if ( params_str[i] == 'l' )
		{
			if (l_flag) continue;
			l_flag = 2;
			correct_flags++;
			continue;
		}
		if ( params_str[i] == 't' )
		{
			if (t_flag) continue;
			if ( params_str[i+1] == '=' )
			{
				int j=i+2;
				for (; params_str[j]; j++)
					if ( (params_str[j] >= '0') && (params_str[j] <= '9') )
						t_flag_len++;
					else break;

				if (t_flag_len > 0)
				{
					int k=i+2;
					int size = k+t_flag_len;
					int j;
					*time_ms_str = malloc(sizeof(char) * t_flag_len + 1);
					if ( !(*time_ms_str) )
						continue;

					for (j = 0; k < size; j++, k++)
						(*time_ms_str)[j] = params_str[k];
					(*time_ms_str)[j] = '\0';
				
					*time_ms = str_to_int(params_str, t_flag_len, i+2);
					t_flag = 1;
				}

				if (t_flag)
					correct_flags++;
			}
		}
		if ( correct_flags >= 3 )
			break;
	}
	int flag_sum = s_flag | l_flag | t_flag;
	/*printf("time_ms_str = %s\n"
			   "time_ms = %u\n", *time_ms_str, *time_ms );*/

	switch (flag_sum)
	{
		case 1:
			;const char* templ_flags1 = "s=0|l=0|t=";
			*correct_flags_str = make_cor_flags_str(flag_sum, templ_flags1, t_flag_len, *time_ms_str);
			if ( !(*correct_flags_str) )
				return 0;
			break;
		case 2:
			;const char* templ_flags2 = "s=0|l=1|t=10000";
			*correct_flags_str = make_cor_flags_str(flag_sum, templ_flags2, 0, 0);
			if ( !(*correct_flags_str) )
				return 0;
			break;
		case 3:
			;const char* templ_flags3 = "s=0|l=1|t=";
			*correct_flags_str = make_cor_flags_str(flag_sum, templ_flags3, t_flag_len, *time_ms_str);
			if ( !(*correct_flags_str) )
				return 0;
			/*printf("[*]time_ms_str = %s\n"
					"[*]str_flag_size = %d\n", *time_ms_str, str_flag_size);*/
						/*printf("[*]correct_flags_str = %s\n", *correct_flags_str);*/
			break;
		case 4:
			;const char* templ_flags4 = "s=1|l=0|t=10000";
			*correct_flags_str = make_cor_flags_str(flag_sum, templ_flags4, 0, 0);
			if ( !(*correct_flags_str) )
				return 0;
			break;
		case 5:
			;const char* templ_flags5 = "s=1|l=0|t=";
			*correct_flags_str = make_cor_flags_str(flag_sum, templ_flags5, t_flag_len, *time_ms_str);
			if ( !(*correct_flags_str) )
				return 0;
			break;
		case 6:
			;const char* templ_flags6 = "s=1|l=1|t=10000";
			*correct_flags_str = make_cor_flags_str(flag_sum, templ_flags6, 0, 0);
			if ( !(*correct_flags_str) )
				return 0;
			break;
		case 7:
			;const char* templ_flags7 = "s=1|l=1|t=";
			*correct_flags_str = make_cor_flags_str(flag_sum, templ_flags7, t_flag_len, *time_ms_str);
			if ( !(*correct_flags_str) )
				return 0;
			break;
		default:
			free(*time_ms_str);
			return 0;
	}

	if ( t_flag )
	{
		if ( *time_ms_str )
		{
			free(*time_ms_str);
			*time_ms_str = NULL;
		}
	}

	return 1;
}
void check_port_argument(const char* port, char** port_buf, unsigned int* port_start_num, unsigned int* port_end_num)
{
	char buffer[2][100];
	unsigned int dash = 0;
	unsigned int port_len = strlen(port);
	*port_buf = malloc(sizeof(char) * port_len + 1);

	if ( !(*port_buf) )
	{
		*port_start_num = MIN_PORT_NUM;
		*port_end_num = MAX_PORT_NUM;
		return;
	}

	int i;
	for ( i = 0; i < port_len; i++ )
		(*port_buf)[i] = port[i];
	(*port_buf)[i] = '\0';
	
	/*printf("*port_buf = %s\n", *port_buf);*/

	int j = 0;
	for ( i = 0; (*port_buf)[i]; i++ )
	{
		if ( (*port_buf)[i] == '-' )
		{
			dash = 1;
			char* istr = strtok((*port_buf), "-");
			while ( istr )
			{
				if (j < 2)
				{
					int z;
					for (z = 0; istr[z] && (z < 50); z++)
						buffer[j][z] = istr[z];
					buffer[j][z] = '\0';
					j++;
					istr = strtok(NULL, "-");
				}
				else break;
			}
			break;
		}
		if ( ((*port_buf)[i] < '0') || ((*port_buf)[i] > '9') )
		{
			(*port_start_num) = MIN_PORT_NUM;
			(*port_end_num) = MAX_PORT_NUM;
			free(*port_buf);
			return;
		}
	}
	
	if ( !dash )
	{
		int port_number;
		int num_len = strlen(*port_buf);
		if (num_len > 5)
			num_len = 5;
		
		port_number = str_to_int((*port_buf), num_len, 0);

		(*port_start_num) = (port_number % MAX_PORT_NUM);
		(*port_end_num) = (port_number % MAX_PORT_NUM);
	}
	else
	{
	/*	printf("buffer[0] = %s\n"
			   "buffer[1] = %s\n"
			   "atoi(buffer[0]) returns %d\n"
			   "atoi(buffer[1]) returns %d\n", buffer[0], buffer[1], atoi(buffer[0]), atoi(buffer[1]));
	*/

		int min_num = 0, max_num = 0;

		if ( (!(min_num = atoi(buffer[0]))) || (!(max_num = atoi(buffer[1]))) )
		{
			(*port_start_num) = MIN_PORT_NUM;
			(*port_end_num) = MAX_PORT_NUM;
			free(*port_buf);
			return;
		}
		
		if ( (min_num < MIN_PORT_NUM) || (min_num > MAX_PORT_NUM) )
			min_num = MIN_PORT_NUM;
		if ( (max_num < MIN_PORT_NUM) || (max_num > MAX_PORT_NUM) )
			max_num = MAX_PORT_NUM;


		(*port_start_num) = min_num;
		(*port_end_num) = max_num;
	}
	
	free(*port_buf);
	
	/*
	printf("dash = %d\n", dash);
	printf("%s", "buffer[0] = ");
	for (i = 0; buffer[0][i]; i++)
		printf("%c", buffer[0][i]);
	printf("%s","\n");
	printf("%s", "buffer[1] = ");
	for (i = 0; buffer[1][i]; i++)
		printf("%c", buffer[1][i]);
	printf("%s","\n");
	*/
}

#endif
