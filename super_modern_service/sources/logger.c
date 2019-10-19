/*
 * Super modern service by d0now
 * for belluminar 2019
 * git : github.com/d0now/2019_belluminar
*/

#include "logger.h"

int logger_init(const char *path) {

    if ((logger = open(path, O_WRONLY | O_CREAT, 0600)) == -1)
        return -1;

    logger_write("====== Log started ======\n");

    return 0;
}

int logger_write(const char *string) {

    int len = strlen(string);

    if (write(logger, string, len) != len)
        return -1;

    return 0;
}