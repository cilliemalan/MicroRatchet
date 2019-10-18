// syscalls for embedded environments
#include <stdlib.h>
/* Includes */
#include <sys/stat.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <sys/times.h>

/* Variables */
//#undef errno
extern int errno;
extern int __io_putchar(int ch) __attribute__((weak));
extern int __io_getchar(void) __attribute__((weak));

register char *stack_ptr asm("sp");

char *__env[1] = {0};
char **environ = __env;

int _getpid(void)
{
    return 1;
}

int _kill(int pid, int sig)
{
    errno = EINVAL;
    return -1;
}

void _exit(int status)
{
    _kill(status, -1);
    for(;;) {}
}

__attribute__((weak)) int _read(int file, char *ptr, int len)
{
    int DataIdx;

    for (DataIdx = 0; DataIdx < len; DataIdx++)
    {
        *ptr++ = __io_getchar();
    }

    return len;
}

__attribute__((weak)) int _write(int file, char *ptr, int len)
{
    for (int i = 0; i < len; i++)
    {
        __io_putchar(*ptr++);
    }
    return len;
}

int _close(int file)
{
    return -1;
}

int _fstat(int file, struct stat *st)
{
    st->st_mode = S_IFCHR;
    return 0;
}

int _isatty(int file)
{
    return 1;
}

int _lseek(int file, int ptr, int dir)
{
    return 0;
}

int _open(char *path, int flags, ...)
{
    return -1;
}

int _wait(int *status)
{
    errno = ECHILD;
    return -1;
}

int _unlink(char *name)
{
    errno = ENOENT;
    return -1;
}

int _times(struct tms *buf)
{
    return -1;
}

int _stat(char *file, struct stat *st)
{
    st->st_mode = S_IFCHR;
    return 0;
}

int _link(char *old, char *new)
{
    errno = EMLINK;
    return -1;
}

int _fork(void)
{
    errno = EAGAIN;
    return -1;
}

int _execve(char *name, char **argv, char **env)
{
    errno = ENOMEM;
    return -1;
}

int mkdir(const char* blash, mode_t mode)
{
    return 0;
}

char *getcwd(char *buf, size_t size)
{
    return "/";
}

int _gettimeofday(struct timeval *tv, struct timezone *tz)
{
    return 0;
}

void __sync_synchronize()
{
    
}

// hardcoded for now
#define RAMORIGIN ((unsigned int)0x20000000)
#define RAMSIZE ((unsigned int)0x18000)

static char *__heap_end = (char*)RAMORIGIN;

void* _sbrk(int incr)
{
	char *prev_heap_end;

	prev_heap_end = __heap_end;
	if (__heap_end + incr > (char*)((void*)(RAMORIGIN + RAMSIZE)))
	{
		errno = ENOMEM;
		return (void*) -1;
	}

	__heap_end += incr;

	return (void*) prev_heap_end;
}
