#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> //strtok_r 
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#ifdef VM
#include "vm/vm.h"
#endif

static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
static void __do_fork (void *);

/* General process initializer for initd and other process. */
static void
process_init (void) {
	struct thread *current = thread_current ();
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. <- 첫 프로세스 생성시에만 initd() 쓰임!
 * 
 * 
 * 
 * 
 * */
tid_t
process_create_initd (const char *file_name) {
	char *fn_copy;
	tid_t tid;

	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy (fn_copy, file_name, PGSIZE);

	/* project 2. command line parsing */
	// 프로세스 이름만을(args-single) 프로세스 이름으로 넘겨주어야 하므로, 파싱 작업을 추가해준다.  
	char *token, *last;
	token = strtok_r(file_name, " ", &last);
	tid = thread_create (token, PRI_DEFAULT, initd, fn_copy);
	/* project 2. command line parsing */

	/* Create a new thread to execute FILE_NAME. */
	tid = thread_create (file_name, PRI_DEFAULT, initd, fn_copy); //initd()는 첫번째 유저 프로세스를 실행하는 함수. 그 이후부터는 fork()로 프로세스를 생성한다. "Notice that THIS SHOULD BE CALLED ONCE." 의 이유!
	if (tid == TID_ERROR)
		palloc_free_page (fn_copy);
	return tid;
}

/* A thread function that launches first user process. ..첫 번째 프로세스 생성시에만 쓰임에 유의! */
static void
initd (void *f_name) {
#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);
#endif

	process_init ();

	if (process_exec (f_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED ();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t
process_fork (const char *name, struct intr_frame *if_ UNUSED) {
	/* Clone current thread to new thread.*/
	return thread_create (name,
			PRI_DEFAULT, __do_fork, thread_current ());
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {
	struct thread *current = thread_current ();
	struct thread *parent = (struct thread *) aux;
	void *parent_page;
	void *newpage;
	bool writable;

	/* 1. TODO: If the parent_page is kernel page, then return immediately. */

	/* 2. Resolve VA from the parent's page map level 4. */
	parent_page = pml4_get_page (parent->pml4, va);

	/* 3. TODO: Allocate new PAL_USER page for the child and set result to
	 *    TODO: NEWPAGE. */

	/* 4. TODO: Duplicate parent's page to the new page and
	 *    TODO: check whether parent's page is writable or not (set WRITABLE
	 *    TODO: according to the result). */

	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
	if (!pml4_set_page (current->pml4, va, newpage, writable)) {
		/* 6. TODO: if fail to insert page, do error handling. */
	}
	return true;
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void
__do_fork (void *aux) {
	struct intr_frame if_;
	struct thread *parent = (struct thread *) aux;
	struct thread *current = thread_current ();
	/* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
	struct intr_frame *parent_if;
	bool succ = true;

	/* 1. Read the cpu context to local stack. */
	memcpy (&if_, parent_if, sizeof (struct intr_frame));

	/* 2. Duplicate PT */
	current->pml4 = pml4_create();
	if (current->pml4 == NULL)
		goto error;

	process_activate (current);
#ifdef VM
	supplemental_page_table_init (&current->spt);
	if (!supplemental_page_table_copy (&current->spt, &parent->spt))
		goto error;
#else
	if (!pml4_for_each (parent->pml4, duplicate_pte, parent))
		goto error;
#endif

	/* TODO: Your code goes here.
	 * TODO: Hint) To duplicate the file object, use `file_duplicate`
	 * TODO:       in include/filesys/file.h. Note that parent should not return
	 * TODO:       from the fork() until this function successfully duplicates
	 * TODO:       the resources of parent.*/

	process_init ();

	/* Finally, switch to the newly created process. */
	if (succ)
		do_iret (&if_);
error:
	thread_exit ();
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. 
 *
 * 현재 실행중인 프로세스의 콘텍스트를 인자로 받은 f_name으로 콘텍스트 스위칭한다. 
 * process_exec에 콘텍스트 스위칭의 기능이 있는 이유? -> 유휴 스레드를 포함해 어떤 스레드가 먼저 돌고 있었을 테니, 유저가 입력한 명령어를 실행하기 앞서 먼저 콘텍스트 스위칭 해줘야 한다.!
 *
 * process_exec의 역할 
 * 1. argument_parsing
 * 2. 유저 커널 스택에 정보올리기 (load)
 * 
 */
int
process_exec (void *f_name) { //유저가 입력한 명령어를 토대로 프로그램의 메모리 적재 및 실행을 담당하는 함수. 여기에 파일 이름을 인자로 받아 문자열로 저장하지만 현재, 파일이름과 옵션이 분리가 되지 않은 상황이다. 
	char *file_name = f_name; // f_name은 문자열인데 위에서 void* 로 넘겨받았으니, 문자열로 인식하기 위해서는 char형으로의 형변환이 필요하다. 
	bool success;

	/* --- Project 2: Command_line_parsing ---*/
	// 원본 file name을 Copy해온다.
	char file_name_copy[128]; // 스택에 저장한다
	memcpy(file_name_copy, file_name, strlen(file_name)+1); //strlen은 센티널 문자를 포함하지 않으므로, 원 문자열에 포함된 센티널을 포함하고자 +1
	/* --- Project 2: Command_line_parsing ---*/
	//파싱 되기 전의 원본 문자열을 다른 함수에서 사용할 수 도 있드니, 미리 memcpy를 통해 복사본을 만들어준다. 

	/* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */


	//인터럽트 프레임이란? : 인터럽트 발생시, 콘텍스트 스위칭 전에 레지스터 안에 담긴 정보를 백업 해 놓는 구조체이다. 
	struct intr_frame _if; // '인터럽트 프레임' 내 구조체 멤버 및 요소들에 필요한 정보를 담음.
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;
	

	/* We first kill the current context */
	process_cleanup ();
	// 현재 스레드에 새로운 실행 파일을 담기 전에, 먼저 현재 프로세스에 할당된 page directory를 지움으로서, 현 프로세스에 담긴 context를 비워준다.

	/* And then load the binary */
	success = load (file_name, &_if); //_if 는 콘텍스트 스위칭에 필요한 정보를 담고있따. 
	//file_name과 인터럽트 프레임을 현 프로세스에 load 한다. 
	//load의 반환형이 bool type이므로, load에 성공시 success 는 1(실패시 0)
	//이 떄 file_name은 파싱 된 f_name의 첫 문자열이다. 

	/* If load failed, quit. */
	if (!success)
		return -1;

	/* --- Project 2: Command_line_parsing ---*/
	hex_dump(_if.rsp, _if.rsp, KERN_BASE - _if.rsp, true);
	// palloc_free_page (file_name); // file_name : 프로그램 파일을 받기 위한 임시변수이니, load끝나면 메모리 반환해야. 
	/* --- Project 2: Command_line_parsing ---*/

	/* Start switched process. */
	do_iret (&_if);
	NOT_REACHED ();


}

/* --- Project 2: Command_line_parsing ---*/
/* 인자를 스택에 쌓음 */
void argument_stack(char **argv, int argc, struct intr_frame *if_) { //if_ 가 인터럽트 스택 프레임으로, 여기에다 쌓음


	/* insert arguments' address 
	* 	인자들의 주소이므로, 포인터들의 배열인 포인터 배열로 받는 것이다.
	*/ 
	char *arg_address[128]; // char *arr[128]은 메모리 128곳을 가리키는 배열(포인터들의 배열... 배열의 요소가 포인터들로 이루어져 있다... 이때 배열 요소의 자료형이 char* !
	
	//거꾸로 삽입하는 이유는, 스택이 downward로 확장되기 떄문이다. 
	
	/* ex. 끝의 NULL 값(arg[4] 제외하고 스택에 저장한다 (arg[0] ~arg[3])*/
	for (int i = argc-1; i>=0; i--) { 
		int argv_len = strlen(argv[i]);
		/* 
		if_->rsp 는 현재 유저스택의 현 위치를 가리킨다. 
		이떄 strlen을 이용, 각 인자의 크기를 읽는데, 이때 sentinel 이 빠져있으니 포함하고자 argv_len +1의 크기만큼 스택포인터를
		내리고, 늘려준 공간에 memcpy를 해줌
		 */
		if_->rsp = if_->rsp - (argv_len + 1);
		memcpy(if_->rsp, argv[i], argv_len+1);
		arg_address[i] = if_->rsp; // arg_address 배열에 현재 문자열의 시작 주소 위치를 저장
	}

	/* word-align: 8의 배수 맞추기 위한 padding 삽입*/
	while (if_->rsp % 8 != 0) //8의 배수가 될때까지, 주소값을 1씩 내리며, 
	{
		if_->rsp--; 
		*(uint8_t *) if_->rsp = 0; // 빈 데이터 값에다 0을 삽입한다. (결국 8바이트 저장!)
		//의문 : 화살표 연산자 인데, "*(uint8_t *) if_->r"이 아니라 (uint8_t *) if_->r 가 맞는 거 아닌가?
	}

	/* 센티널 포함해서 주소값 자체를 삽입*/
	
	for (int i = argc; i >=0; i--) 
	{ 
		// NULL 값 포인터도 같이 넣고, 
		if_->rsp = if_->rsp - 8; // 스택 포인터를 8바이트만큼 내린다.
		if (i == argc) { // 가장 위에는 NULL이 아닌 0을 넣는다.
			memset(if_->rsp, 0, sizeof(char **));
		} else { // 나머지에는 arg_address 안에 들어있는 값 가져오기
			memcpy(if_->rsp, &arg_address[i], sizeof(char **)); // char 포인터 크기: 8바이트
		}	
	}
	

	

	if_->R.rsi = if_->rsp;
	if_->R.rdi = argc;

	/* fake address(0) 저장*/
	if_->rsp = if_->rsp - 8;
	memset(if_->rsp, 0, sizeof(void *));

}





/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. 
 * 
 * hex_dump를 이용하고 싶지만, 현재, 자식 프로세스를 기다리는 도중에 -1이 리턴되어 오류발생. 따라서 pintos에게 형재 자식을 기다리고 있다고 (속이기) 위해, 무한 루프를 건다. 
 * */
int
process_wait (tid_t child_tid UNUSED) {
	/* XXX: Hint) The pintos exit if process_wait (initd), we recommend you
	 * XXX:       to add infinite loop here before
	 * XXX:       implementing the process_wait. */

	/* --- Project 2: Command_line_parsing ---*/
	while (1){}
	/* --- Project 2: Command_line_parsing ---*/

	return -1;
}

/* Exit the process. This function is called by thread_exit (). */
void
process_exit (void) {
	struct thread *curr = thread_current ();
	/* TODO: Your code goes here.
	 * TODO: Implement process termination message (see
	 * TODO: project2/process_termination.html).
	 * TODO: We recommend you to implement process resource cleanup here. */

	process_cleanup ();
}

/* Free the current process's resources. */
static void
process_cleanup (void) {
	struct thread *curr = thread_current ();

#ifdef VM
	supplemental_page_table_kill (&curr->spt);
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL) {
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate (NULL);
		pml4_destroy (pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	pml4_activate (next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update (next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. 
 * 
 * 	실행파일(ELF excutable)의 file_name을 메모리로 적재해 실행하고, rip(다음 실행할 명령어의 주소 보관함)에 엔트리 포인트를 저장
 *  process_exec()이 'caller'로서, load()를 호출하게 되는데, 이 때 file_name 인자로, process_exec에서 받은 '명령 커맨드'전체가 들어온다.
 * */
static bool
load (const char *file_name, struct intr_frame *if_) {
	struct thread *t = thread_current ();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	/* --- Project 2: Command_line_parsing ---*/
	char *arg_list[128];
	char *token, *save_ptr; //함수 strtok_r에서 쓰기위한 임시 변수. save_ptr 는  문자열을 자르고 남은 문자열의 가장 앞을 가리키는 포인터의 주소값이다. 
	int token_count = 0;
	
	token = strtok_r(file_name, " ",  &save_ptr); //첫번째 이름이 나올 것
	arg_list[token_count] = token;

	while (token != NULL) {
		token = strtok_r (NULL, " ", &save_ptr);
		token_count++;
		arg_list[token_count] = token;
	}
	/* --- Project 2: Command_line_parsing ---*/

	/* Allocate and activate page directory. */
	t->pml4 = pml4_create ();
	if (t->pml4 == NULL)
		goto done;
	process_activate (thread_current ());

	/* Open executable file. */
	file = filesys_open (file_name);
	if (file == NULL) {
		printf ("load: %s: open failed\n", file_name);
		goto done;
	}

	/* Read and verify executable header. */
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 0x3E // amd64
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Phdr)
			|| ehdr.e_phnum > 1024) {
		printf ("load: %s: error loading executable\n", file_name);
		goto done;
	}

	/* Read program headers. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) {
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length (file))
			goto done;
		file_seek (file, file_ofs);

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type) {
			case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_STACK:
			default:
				/* Ignore this segment. */
				break;
			case PT_DYNAMIC:
			case PT_INTERP:
			case PT_SHLIB:
				goto done;
			case PT_LOAD:
				if (validate_segment (&phdr, file)) {
					bool writable = (phdr.p_flags & PF_W) != 0;
					uint64_t file_page = phdr.p_offset & ~PGMASK;
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
					uint64_t page_offset = phdr.p_vaddr & PGMASK;
					uint32_t read_bytes, zero_bytes;
					if (phdr.p_filesz > 0) {
						/* Normal segment.
						 * Read initial part from disk and zero the rest. */
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
								- read_bytes);
					} else {
						/* Entirely zero.
						 * Don't read anything from disk. */
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}
					if (!load_segment (file, file_page, (void *) mem_page,
								read_bytes, zero_bytes, writable))
						goto done;
				}
				else
					goto done;
				break;
		}
	}

	/* Set up stack. */
	if (!setup_stack (if_))
		goto done;

	/* Start address. */
	if_->rip = ehdr.e_entry;

	/* TODO: Your code goes here.
	 * TODO: Implement argument passing (see project2/argument_passing.html). 
	 * argument passing(인자값을 스택에 올리는 argument_stack() 실행!)
	 * arg_list는 문자열의 배열! 첫번째 문자열의 주소가 주어지며, 각 문자열들 간에는 널문자로 구분된다. 128칸에는 문자열의 문자가 담기거나, 문자열간 구분을 위한 널문자가 담긴다. 
	 */
	/* --- Project 2: Command_line_parsing ---*/
	argument_stack(arg_list, token_count, if_); // 인터럽트 프레임을 인자로 받는 것은, 인터럽트 프레임 자체를 스택에 올리고자 한 것이 아니고, 인터럽트 프레임의 구조체 내 특정값인 rsp에 인자를 넘겨주기 위해서이다. 이후 do_iret()이 이 인터럽트 프레임을 스택에 올림.
	/* --- Project 2: Command_line_parsing ---*/

	success = true;

done:
	/* We arrive here whether the load is successful or not. */
	file_close (file);
	return success;
}


/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length (file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr ((void *) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			printf("fail\n");
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool
setup_stack (struct intr_frame *if_) {
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) {
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page (kpage);
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

static bool
lazy_load_segment (struct page *page, void *aux) {
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		void *aux = NULL;
		if (!vm_alloc_page_with_initializer (VM_ANON, upage,
					writable, lazy_load_segment, aux))
			return false;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack (struct intr_frame *if_) {
	bool success = false;
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */

	return success;
}
#endif /* VM */
