#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"


void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual.
 * 
 * 
 * syscall 명령(어셈블리어)은 x86-64에서 시스템 콜을 호출하는 가장 일반적 수단. 
 * 즉, syscall은 사용자 프로그램이 시스템콜을 호출하기 위한 수단. 
 *  */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void 
check_address(void *addr) {
	struct thread *t = thread_current();
	/* --- Project 2: User memory access --- */
	// if (!is_user_vaddr(addr)||addr == NULL) 
	//-> 이 경우는 유저 주소 영역 내에서도 할당되지 않는 공간 가리키는 것을 체크하지 않음. 그래서 
	// pml4_get_page를 추가해줘야!
	if (!is_user_vaddr(addr)||addr == NULL||
	pml4_get_page(t->pml4, addr)== NULL)
	{
		exit(-1);
	}
}


void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}


/*
* 특정 작업은 유저 프로그램에서 직접 다루지 (접근하지) 못하니, 커널에다 시스템콜을 날리면, 커널이 대신 작업을 해준 뒤 결과값만 
* 해당 사항을 요청한 프로그램에게 넘겨준다. (isolation 차원에서 보안 상 장점도 있다)
*/
void
syscall_handler (struct intr_frame *f UNUSED) {
	// 시스템 콜(어셈블리어 명령) 구현이 이번 프로젝트 목표:
	// halt(), exit(), create(), remove() 시스템 콜을 구현
	// syscall이 알아서 스택인자를 커널로 옮겨줌
	/* 유저 스택에 저장된 시스템 콜 넘버를 가져옴 */
	int sys_number = f->R.rax; // rax: 시스템 콜 넘버
    /* 
	인자가 들어오는 순서:
	1번째 인자: %rdi
	2번째 인자: %rsi
	3번째 인자: %rdx
	4번째 인자: %r10
	5번째 인자: %r8
	6번째 인자: %r9 
	*/
	// TODO: Your implementation goes here.
	switch(sys_number) {
		case SYS_HALT:
			halt(); //halt()가 호출 될 시 pintos를 종료시킨다. 
		case SYS_EXIT:
			exit(f->R.rdi); //exit()은 현재 실행 중인 프로세스만 종료시킨다. (halt가 핀토스 전체를 종료시키는 것과 차이)
		case SYS_FORK:
			fork(f->R.rdi);	//fork를 통한 프로세스의 계층 구조화 및 재사용은 자원 회수를 용이하게 한다.(다단계가 떠오른다..) 	
		case SYS_EXEC:
			exec(f->R.rdi); // exec 시스템 호출은 기존의 프로세스의 구조는 그대로 두고, 내용만 바꾸어 실행한다.. 코드,데이터 스택영역을 바꾼다. 
		case SYS_WAIT:
			wait(f->R.rdi);
		case SYS_CREATE:
			create(f->R.rdi, f->R.rsi);		
		case SYS_REMOVE:
			remove(f->R.rdi);		
		case SYS_OPEN:
			open(f->R.rdi);		
		case SYS_FILESIZE:
			filesize(f->R.rdi);
		case SYS_READ:
			read(f->R.rdi, f->R.rsi, f->R.rdx);
		case SYS_WRITE:
			write(f->R.rdi, f->R.rsi, f->R.rdx);		
		case SYS_SEEK:
			seek(f->R.rdi, f->R.rdx);		
		case SYS_TELL:
			tell(f->R.rdi);		
		case SYS_CLOSE:
			close(f->R.rdi);	
	}
	printf ("system call!\n");
	thread_exit ();
}


/* 호출 될 시 pintos를 종료시키는 시스템 콜 */
void halt(void){
	power_off();
}

/* pintos 전체가 아닌 현재 실행중인 프로세스만 종료시키는 시스템 콜 */
void exit(int status)
{
	struct thread *t = thread_current();
	printf("%s: exit%d\n", t->name, status); // Process Termination Message
	/* 정상적으로 종료됐다면 status는 0 */
	/* status: 프로그램이 정상적으로 종료됐는지 확인 */
	thread_exit();
}

/*  파일 생성 시스템 콜 */
bool create (const char *file, unsigned initial_size) {
	/* 성공이면 true, 실패면 false */
	check_address(file);
	if (filesys_create(file, initial_size)) {
		return true;
	}
	else {
		return false;
	}
}

/* 파일 제거 시스템 콜 */
bool remove (const char *file) {
	check_address(file);
	if (filesys_remove(file)) {
		return true;
	} else {
		return false;
	}
}