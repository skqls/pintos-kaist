#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"

#include "threads/flags.h"
#include "threads/synch.h"
#include "threads/init.h" 
#include "filesys/filesys.h"
#include "filesys/file.h" 
#include "userprog/gdt.h"
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

	/* -------- project 2-3------------- */
	lock_init(&filesys_lock);
	/* -------- project 2-3------------- */
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
	uintptr_t *rsp = f->rsp;
	check_address((void *) rsp); 
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
		case (SYS_HALT):
			halt();
		case SYS_EXIT:
			exit(f->R.rdi);
			break;
		case SYS_FORK:
			fork(f->R.rdi, f->R.rsi);	
			break;	
		case SYS_EXEC:
			exec(f->R.rdi);
			break;
		case SYS_WAIT:
			wait(f->R.rdi);
			break;
		case SYS_CREATE:
			create(f->R.rdi, f->R.rsi);	
			break;	
		case SYS_REMOVE:
			remove(f->R.rdi);		
			break;
		case SYS_OPEN:
			open(f->R.rdi);		
			break;
		 case SYS_FILESIZE:
		 	filesize(f->R.rdi);
			break;
		case SYS_READ:
			read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE:
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_SEEK:
			seek(f->R.rdi, f->R.rdx);
			break;	
		case SYS_TELL:
			tell(f->R.rdi);
			break;	
		case SYS_CLOSE:
			close(f->R.rdi);
		default:
			thread_exit();
	}
	//thread_exit();
	//printf ("system call!\n");
	//printf("%d", sys_number);
}


/* 호출 될 시 pintos를 종료시키는 시스템 콜 */
void halt(void){
	power_off();
}

/* pintos 전체가 아닌 현재 동작중인 프로세스만 종료시키는 시스템 콜 (이때, 커널에 상태를 리턴하면서 종료!)
 * 부모 프로세스가 현재 유저 프로세스의 종료를 기다리는 중이라면, 그 말은 곧 종료되면서 리턴될 그 상태를 기다린다는 뜻!
 * 따라서, 종료시키려는 스레드의 status를 바꿔줘야 하는데, 이를 위해 exit_status 란 멤버를 스레드 구조체에 만든다음
 * exit에서 해당 구조체 멤버의 값을 인자로 받은 status(종료라면 0이 들어온다.)을 넣은 뒤 thread_exit()을 실행한다. 
 */
void exit(int status)
{
	struct thread *t = thread_current();
	t->exit_status = status;
	printf("%s: exit%d\n", t->name, status); // Process Termination Message
	/* 정상적으로 종료되면 status는 0 
	* 관례적으로 상태 =0 은 성공을 뜻하고, 0이 아닌 값들은 에러를 뜻한다. 
	*/
	/* status: 프로그램이 정상적으로 종료됐는지 확인하는 변수 */
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

//write() 일부 구현 중...
/*
파일 디스크립터 번호(fd)는 동작에 대한 수행 자격을 부여하는 역할(핸들러)을 한다. 
즉,  write()에서 fd값이 STDOUT_FILENO와 같은지를 체크한다. 
이때, STDOUT_FILENO라는 숫자 자체가 콘솔에 출력하는 권한을 부여한다고 볼 수있으며,
이는 운영체제가 사용자 프로세스에게 권한을 주는 것이라고도 볼 수 있다. 

*/
int write (int fd, const void *buffer, unsigned size) {
	check_address(buffer);
	struct file *fileobj = fd_to_struct_filep(fd);
	int read_count;

	lock_acquire(&filesys_lock);
	if (fd == STDOUT_FILENO) {
		putbuf(buffer, size);
		read_count = size;

	}	
	
	else if (fd == STDIN_FILENO) {
		lock_release(&filesys_lock);
		return -1;
	}

	else if (fd >= 2){
		
		if (fileobj == NULL) {
		lock_release(&filesys_lock);
		exit(-1);
		}

		read_count = file_write(fileobj, buffer, size);
		
	}
	lock_release(&filesys_lock);
	return read_count;
}


/* Writes the N characters in BUFFER to the console. 

putbuf(): buffer 안에 들어있는 값 중 size_t n 만큼 console로 출력
이 때, 동기화를 위해(다른 값이 콘솔 출력하는 것을 막고자), 콘솔을 하나의 자원으로 설정한 뒤, console lock을 걸어준다. 
*/
void
putbuf (const char *buffer, size_t n) {
	acquire_console ();
	while (n-- > 0)
		putchar_have_lock (*buffer++);
	release_console ();
}



/*
THREAD_NAME이라는 이름을 가진 현재 프로세스의 복제본인 새 프로세스를 만드는 함수.
피호출자(callee) 저장 레지스터인 %RBX, %RSP, %RBP와 %R12 - %R15를 제외한 레지스터 값을 복제할 필요 x!
자식 프로세스의 pid를 반환. (자식 프로세스에서 반환 값은 0이다. )

부모 프로세스는 자식 프로세스가 성공적으로 복제되었는지 여부를 알 때까지 fork에서 반환해서는 안 된다.
(즉, 자식 프로세스가 리소스를 복제하지 못하면 부모의 fork() 호출이 TID_ERROR를 반환할 것입니다.)
*/
pid_t fork (const char *thread_name);



/*
현재의 프로세스가 cmd_line에서 이름이 주어지는 실행가능한 프로세스로 변경된다. 
이때 주어진 인자들을 전달하고, 성공적으로 진행된다면 어떤 것도 반환하지 않습니다. 
만약 프로그램이 이 프로세스를 로드하지 못하거나 다른 이유로 돌리지 못하게 되면 exit state -1을 반환하며 프로세스가 종료 
이 함수는 exec 함수를 호출한 쓰레드의 이름은 바꾸지 않습니다. 
file descriptor는 exec 함수 호출 시에 열린 상태로 있다는 것을 알아두세요.
*/
int exec (const char *cmd_line);


/*
자식 프로세스 (pid) 를 기다려서 자식의 종료 상태(exit status)를 가져옵니다. 
만약 pid (자식 프로세스)가 아직 살아있으면, 종료 될 때 까지 기다립니다. 
종료가 되면 그 프로세스가 exit 함수로 전달해준 상태(exit status)를 반환합니다. 

만약 pid (자식 프로세스)가 exit() 함수를 호출하지 않고 커널에 의해서 종료된다면 (e.g exception에 의해서 죽는 경우), 
wait(pid) 는  -1을 반환해야 합니다. 

부모 프로세스가 wait 함수를 호출한 시점에서 이미 종료되어버린 자식 프로세스를 기다리도록 하는 것은 완전히 합당합니다만, 
커널은 부모 프로세스에게 자식의 종료 상태를 알려주든지, 커널에 의해 종료되었다는 사실을 알려주든지 해야 합니다.
*/
int wait (pid_t pid);


/*
위의 함수는 file(첫 번째 인자)를 이름으로 하고 크기가 initial_size(두 번째 인자)인 새로운 파일을 생성합니다.
 성공적으로 파일이 생성되었다면 true를 반환하고, 실패했다면 false를 반환합니다. 
 새로운 파일을 생성하는 것이 그 파일을 여는 것을 의미하지는 않습니다: 
 파일을 여는 것은 open 시스템콜의 역할로, ‘생성’과 개별적인 연산입니다.

*/
bool create (const char *file, unsigned initial_size);

/*
위의 함수는 file(첫 번째)라는 이름을 가진 파일을 삭제합니다. 
성공적으로 삭제했다면 true를 반환하고, 그렇지 않으면 false를 반환합니다.
 파일은 열려있는지 닫혀있는지 여부와 관계없이 삭제될 수 있고, 
 파일을 삭제하는 것이 그 파일을 닫았다는 것을 의미하지는 않습니다. 

*/
bool remove (const char *file);



/*
file(첫 번째 인자)이라는 이름을 가진 파일을 여는 함수. 
파일이 성공적으로 열리면 파일 식별자로 불리우는 비음수 정수를 반환하고 실패하면 -1을 반환. 
(ex:  0번은 표준 입력(STDIN_FILENO)을 의미하고 1번은 표준 출력(STDOUT_FILENO)을 의미.  )

각각의 프로세스는 독립적인 파일 식별자"들"을 가지며,  
파일 식별자"들"은 자식 프로세스들에게 상속된다. 
하나의 프로세스에 의해서든 다른 여러개의 프로세스에 의해서든, 
하나의 파일이 두 번 이상 열리면 그때마다 open 시스템콜은 새로운 식별자를 반환합니다. 

하나의 파일을 위한 서로 다른 파일 식별자들은 개별적인 close 호출에 의해서 독립적으로 닫히고 그 한 파일의 위치를 공유하지 않습니다. 
당신이 추가적인 작업을 하기 위해서는 open 시스템 콜이 반환하는 정수(fd)가 0보다 크거나 같아야 한다는 리눅스 체계를 따라야 합니다.
*/
int open (const char *file) {
	check_address(file); // 먼저 해당 주소가 유효한지 체크.
	struct file *file_obj = filesys_open(file); // 파일 객체 정보를 열때는 이미 주어진 함수를 사용 ... filesys_open()
	
	// file_obj가 null인지 확인 (제대로 파일이 생성되었는지 체크하고자)
	if (file_obj == NULL) {
		return -1;
	}
	int fd = add_file_to_fd_table(file_obj); // 만들어진 파일을 스레드 내 fdt 테이블에 추가한다. 

	// 만약 파일open 에 실패할 경우 -1을 받는다. 
	if (fd == -1) {
		file_close(file_obj);
	}

	return fd;

}


 /* 파일을 현재 프로세스의 fdt에 추가 */
 /*
 파일 디스크립터 테이블은 파일을 담는 배열
 thread_create()에서 새로운 스레드 생성 시, fdt를 위한 하나의 페이지를 할당
 */
int add_file_to_fd_table(struct file *file) {
	struct thread *t = thread_current();
	struct file **fdt = t->file_descriptor_table;
	int fd = t->fdidx; //fd값은 2부터 출발
	
	while (t->file_descriptor_table[fd] != NULL && fd < FDCOUNT_LIMIT) {
		fd++;
	}

	if (fd >= FDCOUNT_LIMIT) {
		return -1;
	}
	t->fdidx = fd;
	fdt[fd] = file;
	return fd;

}

/*  fd 값을 넣으면 해당 file을 반환하는 함수 */
struct file *fd_to_struct_filep(int fd) {
	if (fd < 0 || fd >= FDCOUNT_LIMIT) { //fd값이 0보다 작거나, fd 배열의 범위를 넘으면, 파일이 없다는 뜻. 따라서 null포인터를 반환한다. 
		return NULL;
	}

	struct thread *t = thread_current();
	struct file **fdt = t->file_descriptor_table;
	
	struct file *file = fdt[fd];
	return file;
}

/*
위의 함수는 fd(첫 번째 인자)로서 열려 있는 파일의 크기가 몇 바이트인지 반환합니다.*/
int filesize(int fd) {
	struct file *fileobj = fd_to_struct_filep(fd);
	if (fileobj == NULL) {
		return -1;
	}
	file_length(fileobj);

/*
buffer 안에 fd 로 열려있는 파일로부터 size 바이트를 읽습니다.
 실제로 읽어낸 바이트의 수 를 반환합니다 
 (파일 끝에서 시도하면 0). 파일이 읽어질 수 없었다면 -1을 반환합니다.
 (파일 끝이라서가 아닌 다른 조건에 때문에 못 읽은 경우)
*/

int read(int fd, void *buffer, unsigned size) {
	// 유효한 주소인지부터 체크
	check_address(buffer); // 버퍼 시작 주소 체크
	check_address(buffer + size -1); // 버퍼 끝 주소도 유저 영역 내에 있는지 체크
	unsigned char *buf = buffer;
	int read_count;
	
	struct file *fileobj = fd_to_struct_filep(fd);

	if (fileobj == NULL) {
		return -1;
	}

	/* STDIN일 때: */
	if (fd == STDIN_FILENO) {
		char key;
		for (int read_count = 0; read_count < size; read_count++) {
			key  = input_getc();
			*buf++ = key;
			if (key == '\0') { // 엔터값
				break;
			}
		}
	}
	/* STDOUT일 때: -1 반환 */
	else if (fd == STDOUT_FILENO){
		return -1;
	}

	else {
		lock_acquire(&filesys_lock);
		read_count = file_read(fileobj, buffer, size); // 파일 읽어들일 동안만 lock 걸어준다.
		lock_release(&filesys_lock);

	}
	return read_count;
}

/*
인자로 받은 fd를 이용해 먼저 파일을 찾은 뒤, 해당 파일 객체의 pos를 인자로 받은 position으로 변경.
이때 사전에 제공된 함수 file_seek()를 이용.
*/
void seek(int fd, unsigned position) {
	if (fd < 2) {
		return;
	}

	if (fd < 0 || fd >= FDCOUNT_LIMIT) {
		return;
	}
	struct file *file = fd_to_struct_filep(fd);
	check_address(file);
	if (file == NULL) {
		return;
	}
	
	file_seek(file, position);

/*
tell()은 seek()와 비슷하다. 파일을 읽을 때, 어디서부터 읽어야 하는지에 대한 pos를 파일의 구조체 멤버에 정보로 저장한다. 
tell()함수는 fd 값을 인자로 넣으면 해당 파일의 pos를 반환한다. 
*/
unsigned tell (int fd) {
	if (fd <2) {
		return;
	}
	struct file *file = fd_to_struct_filep(fd);
	check_address(file);
	if (file == NULL) {
		return;
	}
	return file_tell(fd);
}

/*
파일 식별자 fd를 닫습니다. 
프로세스를 나가거나 종료하는 것은 묵시적으로 그 프로세스의 열려있는 파일 식별자들을 닫습니다. 
마치 각 파일 식별자에 대해 이 함수가 호출된 것과 같습니다. 
*/
void close (int fd);
