// syscalls for embedded environments
#include <sys/stat.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <time.h>
#include <string.h>
#include <memory.h>
#include <sys/time.h>
#include <sys/times.h>

extern int errno;

#define PUART0_DR ((volatile uint32_t *)0x09000000)

int __io_getchar(void)
{
    volatile uint32_t *UART0_DR = PUART0_DR;
    return *UART0_DR;
}

int __io_putchar(int c)
{
    volatile uint32_t *UART0_DR = PUART0_DR;
    *UART0_DR = (uint32_t)(c);
    return 0;
}

register char *stack_ptr asm("sp");

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
    for (;;)
    {
    }
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

int mkdir(const char *blash, mode_t mode)
{
    return 0;
}

char *getcwd(char *buf, size_t size)
{
    const char cwd[] = "/";
    if (!buf || size < sizeof(cwd))
        return NULL;
    memcpy(buf, cwd, sizeof(cwd));
    return buf;
}

int _gettimeofday(struct timeval *tv, struct timezone *tz)
{
    return 0;
}

void __sync_synchronize()
{
}

extern const unsigned int _ebss;
register char *stack_ptr asm("sp");

static char *__heap_end = 0;

void *_sbrk(int incr)
{
    char *prev_heap_end;

    if (!__heap_end)
    {
        __heap_end = (char *)&_ebss;
    }

    prev_heap_end = __heap_end;
    if (__heap_end + incr > stack_ptr)
    {
        errno = ENOMEM;
        return (void *)-1;
    }

    __heap_end += incr;

    return (void *)prev_heap_end;
}

#define NUM_ENV_VARS 4
char **environ;
static char *__environblocku[NUM_ENV_VARS];
static char __environblockc[128];

// load environment before static initializers
// because some module initializers expect them to be ready
void __preinit()
{
    char *vars[NUM_ENV_VARS] = {
        "TERM=xterm",
        0
    };

    char* environblockc = __environblockc;
    for (int i = 0; i < NUM_ENV_VARS; i++)
    {
        char* var = vars[i];
        if (var)
        {
            size_t len = strlen(var);
            if (environblockc + len > __environblockc + sizeof(__environblockc))
            {
                break;
            }
            __environblocku[i] = environblockc;
            memcpy(environblockc, var, len);
            environblockc += len;
        }
        else
        {
            __environblocku[i] = 0;
        }
    }

    environ = __environblocku;
}

extern int main(int argc, char **argv);
int __main()
{
    int argc = 1;
    char *argv[] = {"/tests"};

    return main(argc, argv);
}