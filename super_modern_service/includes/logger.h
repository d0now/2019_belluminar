/*
 * Super modern service by d0now
 * for belluminar 2019
 * git : github.com/d0now/2019_belluminar
*/

#ifndef _LOGGER_H_
#define _LOGGER_H_

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#ifdef DEBUG
#define LOG_VA(...) {                               \
    snprintf(logbuf, sizeof(logbuf), __VA_ARGS__);  \
    logger_write(logbuf);                           \
}
#else
#define LOG_VA(...)
#endif

int logger;
char logbuf[1024];

int logger_init(const char *path);
int logger_write(const char *string);

#endif