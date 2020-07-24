#include <stdint.h>
#include <stdio.h>

////
// the start up file includes the very first stuff that
// will go into the firmware binary, as well as the very
// first code to execute.
//
// The first data in the firmware binary is the interrupt
// vector, which we declare here. This is not the final
// interrupt vector and only includes the reset function.
// The interrupt vector is changed in system_init.
//
// the __reset_irq function is the first code to be executed.
// It makes sure that all data and bss sections are populated
// correctly, calls std c lib initializers, and system_init,
// before calling main.

// types
typedef void (*isr_handler)();

// external definitions defined by the linker
extern "C"
{
    extern uint32_t _sidata;
    extern uint32_t _sdata;
    extern uint32_t _edata;
    extern uint32_t _sbss;
    extern uint32_t _ebss;
    extern uint32_t _estack;

    extern void (*__preinit_array_start[])(void);
    extern void (*__preinit_array_end[])(void);
    extern void (*__init_array_start[])(void);
    extern void (*__init_array_end[])(void);

    void __reset_irq() __attribute__((naked, noreturn, section(".startup")));
    void __libc_init_array();

    int main(int argc, const char** argv);
}

// forwards
static void system_init();
extern isr_handler interrupt_vector[128] __attribute__((aligned(128)));

// the base interrupt vector run out of startup. The first word is the
// initial value of the stack pointer and the second word is the
// location of the reset function. No other functions are given here
// as system_init will set the interrupt vector to the final one.
// note: the fault vector will be invalid so confusing things will happen
// if a fault happens before VTOR is set
const void* isr_vector[2] __attribute__((section(".vectortable.isr"))) =
{ &_estack, (const void*)__reset_irq };

// the entry point for the application out of cold boot
void __reset_irq()
{
    // load the stack into sp, though it should
    // already be set by the processor from the
    // interrupt vector.
    asm("ldr sp,=_estack");

    // copy in data
    for (uint32_t* d = &_sdata, *s = &_sidata; d < &_edata; s++, d++)
    {
        // the voltailes are so this does not get optimised to memset/memcpy
        *((volatile uint32_t*)d) = *s;
    }

    // clear BSS
    for (uint32_t* d = &_sbss; d < &_ebss; d++)
    {
        *((volatile uint32_t*)d) = 0;
    }

    // basic system initalization
    system_init();

    // call module initializers.
    __libc_init_array();

    // into the main function
    static const char* args[] = {
        "microratchettests",
        "--gtest_color=yes",
    };
    main(2, args);

    // main is not allowed to exit.
    for (;;)
    {
    }
}





// CMSIS defines a bunch of stuff
// so if we don't have it define
// some stuff here
#ifndef __CM_CMSIS_VERSION

#if !(defined(__GNUC__) || defined(__clang__))
#error unsupported ARM compiler
#endif

// system control block
typedef struct SCB_s
{
    volatile const uint32_t CPUID;
    volatile uint32_t ICSR;
    volatile uint32_t VTOR;
    volatile uint32_t AIRCR;
    volatile uint32_t SCR;
    volatile uint32_t CCR;
    volatile uint8_t  SHP[12U];
    volatile uint32_t SHCSR;
} SCB_t;

#define SCB_BASE 0xE000E000
#define SCB ((SCB_t*)SCB_BASE)

#define __disable_irq() asm("cpsid i" : : : "memory")
#define __enable_irq() asm("cpsie i" : : : "memory")
#define __DSB() asm("dsb 0xF":::"memory")
#define __NOP() asm("nop")
#define __enable_fault_irq() asm("cpsie f" : : : "memory")
#define __disable_fault_irq() asm("cpsid f" : : : "memory")

#define NVIC_SystemReset()                                \
    do                                                    \
    {                                                     \
        __DSB();                                          \
        SCB->AIRCR = (uint32_t)((0x5FA << 16) |           \
                                (SCB->AIRCR & (7 << 8)) | \
                                (1 << 2));                \
        __DSB();                                          \
        for (;;)                                          \
            __NOP();                                      \
    } while (0);

#endif

#define Raise_Fault()            \
    do                           \
    {                            \
        __DSB();                 \
        SCB->SHCSR |= (1 << 12); \
        __DSB();                 \
        for (;;)                 \
            __NOP();             \
    } while (0)

#define WAITFOR(x)                          \
    do                                      \
    {                                       \
        uint32_t scs = SystemCoreClock / 8; \
        for (uint32_t i = 0; i < scs; i++)  \
        {                                   \
            if (x)                          \
                break;                      \
        }                                   \
    } while (0);

static void system_init_device()
{
#ifdef STM32L4xx
    // Enable FPU
    SCB->CPACR |= ((3UL << 10 * 2) | (3UL << 11 * 2));

    // Set MSION
    RCC->CR |= RCC_CR_MSION;

    // Reset CFGR
    RCC->CFGR = 0;

    // Turn off other clocks and PLLs
    RCC->CR &= ~(RCC_CR_PLLSAI1ON | RCC_CR_PLLSAI2ON | RCC_CR_PLLON | RCC_CR_HSEON | RCC_CR_CSSON | RCC_CR_HSION);

    // Reset PLLCFGR (default from reference manual)
    RCC->PLLCFGR = 0x00001000U;

    // Reset HSEBYP
    RCC->CR &= RCC_CR_HSEBYP;

    // Disable clock interrupts
    RCC->CIER = 0;
#endif

#ifdef STM32F4xx
    // Enable FPU
    SCB->CPACR |= ((3UL << 10 * 2) | (3UL << 11 * 2));

    // Set HSION
    RCC->CR |= RCC_CR_HSION;

    // Reset CFGR
    RCC->CFGR = 0;

    // Turn off other clocks and PLLs
    RCC->CR &= ~(RCC_CR_HSEON | RCC_CR_PLLON);

    // Reset PLLCFGR (default from reference manual)
    RCC->PLLCFGR = 0x24003010;

    // Reset HSEBYP
    RCC->CR &= RCC_CR_HSEBYP;

    // Disable clock interrupts
    RCC->CIR = 0;
#endif

#ifdef STM32WBxx
    // Enable FPU
    SCB->CPACR |= ((3UL << 10 * 2) | (3UL << 11 * 2));

    // turn on MSI
    RCC->CR |= RCC_CR_MSION;

    // Reset CFGR (default from reference manual)
    RCC->CFGR = RCC_CFGR_HPREF | RCC_CFGR_PPRE1F | RCC_CFGR_PPRE2F;

    // Turn off other clocks and PLLs
    RCC->CR &= ~(RCC_CR_PLLSAI1ON | RCC_CR_PLLON | RCC_CR_HSEON | RCC_CR_CSSON | RCC_CR_HSION | RCC_CR_MSIPLLEN);

    // NOT Resetting LSI1 and LSI2
    // RCC->CSR &= ~(RCC_CSR_LSI1ON | RCC_CSR_LSI2ON)

    // Reset HSI48ON
    RCC->CRRCR &= ~RCC_CRRCR_HSI48ON;

    // Reset PLLCFGR (default from reference manual)
    RCC->PLLCFGR = 0x22041000U;

    // Reset PLLSAI1CFGR (default from reference manual)
    RCC->PLLSAI1CFGR = 0x22041000U;

    // Reset HSEBYP
    RCC->CR &= RCC_CR_HSEBYP;

    // Disable clock interrupts
    RCC->CIER = 0;
#endif
}

static void system_init()
{
    // set the vector table to the correct one
    uint32_t vtor = reinterpret_cast<uint32_t>(&interrupt_vector[0]);
    SCB->VTOR = vtor;

    // device specific initialization
    system_init_device();
}




















////
// This file contains the main interrupt 
// handlers together, as well as the main 
// interrupt vector which is applied in system_init.

static void fault_handler()
{
    // the fault handler is called for
    // several fault conditions. 
	static const char msg[] = " \033[1;5;91m[ ENCOUNTERED FAULT ]\033[0m";

    // here we disable IRQs and reset using
    // the hardware watchdog
    __disable_irq();
    __disable_fault_irq();
    NVIC_SystemReset();
    for (;;)
    {
    }
}

static void nmi_handler()
{
    // NMI is called in some rare fault
    // conditions that one might need
    // to handle here.

    fault_handler();
}

static void svc_handler()
{
    // svc is called when
    // an operating system is configured
}

static void debugmon_handler()
{
    // no idea when this is called
}

static void pendsv_handler()
{
    // pendsv is called when
    // an operating system is configured
}

static void systick_handler()
{
    // the systick handler is called
    // when systick is configured and
    // will interrupt every 1ms in 
    // our configuration.
}



// the main interrupt vector, applied in system_init
isr_handler interrupt_vector[128]
{
    (isr_handler)&_estack,
    __reset_irq,
    nmi_handler,
    fault_handler,
    fault_handler,
    fault_handler,
    fault_handler,
    0,
    0,
    0,
    0,
    svc_handler,
    debugmon_handler,
    0,
    pendsv_handler,
    systick_handler
};

















#include <sys/stat.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <time.h>
//#include <sys/time.h>
//#include <sys/times.h>
#include <cstddef>
#include <errno.h>

#ifdef mkdir
#undef mkdir
#endif

extern "C"
{
    // definitions
#ifdef errno
#undef errno
#endif
    extern int errno;
    const char * ___env[] = {
        "term=xterm",
        nullptr
    };
    char **__env = const_cast<char**>(___env);
    char** environ = __env;

    char * getenv(const char *name);
    char * _getenv(const char *name);
    int __io_putchar(int ch);
    int __io_getchar(void);
    void _putchar(char character);
    int _getpid(void);
    int _kill(int pid, int sig);
    void _exit(int status);
    int _read(int file, char* ptr, int len);
    int _write(int file, char* ptr, int len);
    int _close(int file);
    int _fstat(int file, struct stat* st);
    int _gettimeofday (struct timeval * tp, void * tzvp);
    int _isatty(int file);
    int _lseek(int file, int ptr, int dir);
    int _open(char* path, int flags, ...);
    int _wait(int* status);
    int _unlink(char* name);
    int _times(struct tms* buf);
    int _stat(char* file, struct stat* st);
    int _tell(int file);
    int _link(char* old, char* _new);
    int _fork(void);
    int _execve(char* name, char** argv, char** env);
    int mkdir(const char* name, mode_t mode);
    int _mkdir(const char* name, mode_t mode);
    caddr_t _sbrk(int incr);
    void __cxa_pure_virtual();
    void mr_write_uart(const char* msg, size_t amt);
}

char * getenv(const char *name)
{
    return _getenv_r(_REENT, name);
}

char * _getenv(const char *name)
{
    return _getenv_r(_REENT, name);
}

int __io_putchar(int ch)
{

// for qemu or an actual Stellaris LM3S6965EVB
#ifdef LM3S6965EVB

    static volatile uint32_t *usart_dr = (uint32_t *)0x4000c000;
    static volatile uint32_t *usart_fr = (uint32_t *)0x4000c018;

    // wait for TXFF to clear
    for (volatile size_t i = 0; i < 100000; i++)
    {
        if (!(*usart_fr & 0x20))
        {
            break;
        }
    }

    // set TDR
    *usart_dr = (ch & 0xff);

#endif

// for stm32
#if defined(USART1) || defined(USART2)

// typically usart2 is sent to the virtual
// com port on nucleo boards. Except when
// there is no usart2, in which case it
// is likely usart1
#if defined(USART2)
    USART_TypeDef *usart = USART2;
#else
    USART_TypeDef *usart = USART1;
#endif

    for (volatile size_t i = 0; i < 100000; i++)
    {
        if (usart->ISR & USART_ISR_TXE)
        {
            break;
        }
    }
    usart->TDR = ch & 0xff;

#endif

    return 0;
}

int __io_getchar(void)
{
    return -1;
}

void _putchar(char ch)
{
    __io_putchar(ch);
}

int _getpid(void)
{
    return 1;
}

int _kill(int pid, int sig)
{
    Raise_Fault();
    
    errno = EINVAL;
    return -1;
}

void _exit(int status)
{
    _kill(status, -1);
    while (1)
    {
    }
}

int _read(int file, char* ptr, int len)
{
    return -1;
}

int _write(int file, char *ptr, int len)
{
    if (ptr && len > 0)
    {
        for (size_t i = 0; i < len; i++)
        {
            __io_putchar(ptr[i]);
        }
    }

    return 0;
}

int _close(int file)
{
    return -1;
}

int _fstat(int file, struct stat* st)
{
    st->st_mode = S_IFCHR;
    return 0;
}

int _gettimeofday(struct timeval *tp, void *tzvp)
{

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

int _open(char* path, int flags, ...)
{
    return -1;
}

int _wait(int* status)
{
    errno = ECHILD;
    return -1;
}

int _unlink(char* name)
{
    errno = ENOENT;
    return -1;
}

int _times(struct tms* buf)
{
    return -1;
}

int _stat(char* file, struct stat* st)
{
    st->st_mode = S_IFCHR;
    return 0;
}

int _tell(int file)
{
    errno = EIO;
    return -1;
}

int _link(char* old, char* _new)
{
    errno = EMLINK;
    return -1;
}

int _fork(void)
{
    errno = EAGAIN;
    return -1;
}

int _execve(char* name, char** argv, char** env)
{
    errno = ENOMEM;
    return -1;
}

int mkdir(const char* name, mode_t mode)
{
    errno = EIO;
    return -1;
}

int _mkdir(const char* name, mode_t mode)
{
    errno = EIO;
    return -1;
}

extern char __heap_start__;
extern char __heap_end__;
char* heap_ptr = 0;
caddr_t _sbrk(int incr)
{
    if (!heap_ptr)
    {
        heap_ptr = &__heap_start__;
    }

    char* prev_ptr = heap_ptr;
    char* new_ptr = prev_ptr + incr;

    if (new_ptr > & __heap_end__)
    {
        errno = ENOMEM;
        return (caddr_t)-1;
    }

    heap_ptr = new_ptr;
    return prev_ptr;
}

void __cxa_pure_virtual()
{
    _exit(0);
}

#ifdef __GNUC__
namespace __gnu_cxx
{

    void __verbose_terminate_handler()
    {
        _exit(0);
    }

} // namespace __gnu_cxx

#include <chrono>
namespace std::chrono
{
    inline namespace _V2
    {
        system_clock::time_point system_clock::now() noexcept
        {
            auto ns = chrono::nanoseconds((uint64_t)uwTick * 1000000ULL);
            system_clock::time_point time(ns);
            return time;
        }
    }
}

#endif

void mr_write_uart(const char* msg, size_t amt)
{
    _write(0, const_cast<char*>(msg), static_cast<int>(amt));
}