/*
 * =====================================================================================
 *
 *       Filename:  log.h
 *
 *    Description:  :v
 *
 *        Version:  1.0
 *        Created:  11/23/2016 07:40:12 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (),
 *   Organization:
 *
 * =====================================================================================
 */

#ifndef __LOG_H__
#define __LOG_H__
#undef log
#include <stdio.h>

#define log(...) \
        {FILE *fp = fopen("/data/local/tmp/javazip.log", "a+"); if (fp) {\
        fprintf(fp, __VA_ARGS__);\
        fclose(fp);}}
#endif
