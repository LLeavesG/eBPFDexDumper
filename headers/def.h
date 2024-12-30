#ifndef DEF_H
#define DEF_H

typedef int __kernel_pid_t;

typedef unsigned int __kernel_uid_t;
typedef unsigned int __kernel_uid32_t;

typedef __kernel_pid_t pid_t;
typedef __kernel_uid_t uid_t;

typedef _Bool bool;
enum {
	false = 0,
	true = 1,
};

#endif