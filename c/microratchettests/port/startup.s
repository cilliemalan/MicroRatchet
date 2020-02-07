
.syntax unified

.section	.startup
.global		Reset_Handler
.type		Reset_Handler, %function

Reset_Handler:
	ldr   sp, =_estack



// Copy in the data segment. Copy from _sidata to _sdata
// _sdata, _sidata, and _edata must be aligned
	ldr		r1, =_sidata
	ldr		r2, =_sdata
	ldr		r3, =_edata
	cmp		r1,r2
	beq		2f				// skip if data does not need to be copied
1:
	cmp		r2,r3			// skip copy if no data left
	beq		2f
	ldr		r4, [r1], #4	// load from _sidata -> r4
	str		r4, [r2], #4	// store to _sdata
	b		1b




2:
// Zero bss section, starting at _sbss until _ebss
	mov		r0, #0
	ldr		r1, =_sbss
	ldr		r2, =_ebss
1:
	cmp		r1,r2			// skip copy if no data left
	beq		2f
	str		r0, [r1], #4
	b		1b



2:
	bl		__preinit
    bl		__libc_init_array
	bl		__main


// semihosting quit
	mov		r1, r0
	mov		r0, 0x18
	svc		0xAB

// stick around
0:
    b 0b
    
.size	Reset_Handler, .-Reset_Handler












// Default ISR handler: loops forever for all interrupts
.section	.text.Default_Handler,"ax",%progbits
.type		Default_Handler, %function
Default_Handler:
0:
	b	0b
	.size	Default_Handler, .-Default_Handler

	


/* Vector Table */
.section	.vectortable,"a",%progbits
.type		gvectortable, %object
.size		gvectortable, .-gvectortable


gvectortable:
	.word	_estack
	.word	Reset_Handler
	.word	NMI_Handler
	.word	HardFault_Handler
	.word	MemManage_Handler
	.word	BusFault_Handler
	.word	UsageFault_Handler
	.word	0
	.word	0
	.word	0
	.word	0
	.word	SVC_Handler
	.word	0
	.word	0
	.word	PendSV_Handler
	.word	SysTick_Handler
	.word	Default_Handler
	.word	Default_Handler
	.word	Default_Handler
	.word	Default_Handler
	.word	Default_Handler
	.word	Default_Handler
	.word	Default_Handler
	.word	Default_Handler
	.word	Default_Handler
	.word	Default_Handler
	.word	Default_Handler
	.word	Default_Handler
	.word	Default_Handler
	.word	Default_Handler
	.word	Default_Handler
	.word	Default_Handler
	.word	Default_Handler
	.word	Default_Handler
	.word	Default_Handler
	.word	Default_Handler
	.word	Default_Handler
	.word	Default_Handler
	.word	Default_Handler
	.word	Default_Handler
	.word	Default_Handler
	.word	Default_Handler
	.word	Default_Handler
	.word	Default_Handler
	.word	Default_Handler
	.word	Default_Handler
	.word	Default_Handler
	.word	Default_Handler
	.word	Default_Handler
	.word	Default_Handler
	.word	Default_Handler
	.word	Default_Handler
	.word	Default_Handler
	.word	Default_Handler
	.word	Default_Handler
	.word	Default_Handler
	.word	Default_Handler
	.word	Default_Handler
	.word	Default_Handler
	.word	Default_Handler

.weak	NMI_Handler
.thumb_set NMI_Handler,Default_Handler

.weak	HardFault_Handler
.thumb_set HardFault_Handler,Default_Handler

.weak	MemManage_Handler
.thumb_set MemManage_Handler,Default_Handler

.weak	BusFault_Handler
.thumb_set BusFault_Handler,Default_Handler

.weak	UsageFault_Handler
.thumb_set UsageFault_Handler,Default_Handler

.weak	SVC_Handler
.thumb_set SVC_Handler,Default_Handler

.weak	PendSV_Handler
.thumb_set PendSV_Handler,Default_Handler

.weak	SysTick_Handler
.thumb_set SysTick_Handler,Default_Handler
