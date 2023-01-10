#ifndef _DEBUG_H
#define _DEBUG_H

#define DEBUG_MODULE
#define DEBUG_FILE
#ifdef DEBUG_FILE
extern map<pthread_t, FILE *> dbgfile;
#endif

#ifdef DEBUG_MODULE

#ifdef DEBUG_FILE

#define debug_print(...) fprintf(dbgfile[pthread_self()], __VA_ARGS__)
#else
#define debug_print(...) fprintf(stdout, __VA_ARGS__)
#endif

#else

#define debug_print(...)

#endif

#ifdef DEBUG_FILE
#define progress_print(...) fprintf(dbgfile[pthread_self()], __VA_ARGS__); fflush(dbgfile[pthread_self()])
#define log_print(...)  fprintf(dbgfile[pthread_self()], __VA_ARGS__)
#else
#define progress_print printf
#define log_print printf
#endif
#define warning_print printf
#define distro_print(...) fprintf(stdout, __VA_ARGS__); fflush(stdout)
#endif
