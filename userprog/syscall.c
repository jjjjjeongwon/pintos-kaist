#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "filesys/file.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
typedef int pid_t;

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. 
 */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

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
	
	lock_init(&filesys_lock);
}

/* 주소 값이 유저 영역에서 사용하는 주소 값인지 확인 하는 함수
유저 영역을 벗어난 영역일 경우 프로세스 종료(exit(-1)) */
void check_address(void *addr) {
	 struct thread *curr = thread_current();
//   if (addr < 0x8048000 || addr >= 0xc0000000) {
	if (!is_user_vaddr(addr) || is_kernel_vaddr(addr) || pml4_get_page(curr->pml4,addr) == NULL){
    exit(-1); // 유저 영역을 벗어난 경우 프로세스 종료
  }
}

/*파일 객체에 대한 파일 디스크립터 생성*/
int process_add_file(struct file *f){
	struct thread *curr = thread_current();

	//파일 객체(struct file)를 가리키는 포인터를 File Descriptor 테이블에 추가
	curr->fdt[curr->next_fd] = f;
	//다음 File Descriptor 값 1 증가
	curr->next_fd++;
	//추가된 파일 객체의 File Descriptor 반환
	return curr->next_fd-1;

}

/*프로세스의 파일 디스크립터 테이블을 검색하여 파일 객체의 주소를 리턴*/
struct file *process_get_file(int fd){
	struct thread *curr = thread_current();
	
	return curr->fdt[fd];
}

/*
file_close() 를 호출하여, 파일 디스크립터에 해당하는 파일의 inode reference count를 1씩 감소
해당 파일 디스크립터 엔트리를 NULL로 초기화
*/
void process_close_file(int fd){
	struct thread *curr = thread_current();

	//File Descriptor에 해당하는 파일 객체의 파일을 닫음
	close(fd);
	//File Descriptor 테이블에 해당 엔트리를 NULL 값으로 초기화
	curr->fdt[fd] = NULL;
	}

/*핀토스를 종료시키는 시스템 콜*/
void
halt (void) {
	power_off();
}

/*현재 프로세스를 종료시키는 시스템 콜*/
void
exit (int status) {
	struct thread *curr  = thread_current();
	curr->exit_status = status;
	printf("%s:exit(%d)",thread_name(), status);
	thread_exit();
}

pid_t
fork (const char *thread_name){
	return ;
}

int
exec (const char *cmd_line) {
	return ;
}

int
wait (pid_t pid) {
	return ;
}

/*파일을 생성하는 시스템 콜*/
bool
create (const char *file, unsigned initial_size) {
	check_address(file);
	return filesys_create(file, initial_size);;
}

/*파일을 삭제하는 시스템 콜*/
bool
remove (const char *file) {
	return filesys_remove(file);
}

/* 파일을 열 때 사용하는 시스템 콜 */
int
open (const char *file) {
	struct file *open_file = filesys_open(file);
	check_address(open_file);

	if(!open_file){
		// 실패 시 -1 반환
		return -1;
	}else{
		int fd = process_add_file(open_file);
		if(fd ==-1){
			//프로세스가 종료될 때, 메모리 누수 방지를 위해 프로세스에 열린 모든 파일을 닫음
			file_close(open_file);
		}
		// 성공 시 fd를 생성하고 반환
		return fd;
	}
}

/* 파일의 크기를 알려주는 시스템 콜 */
int
filesize (int fd) {

	struct file *find_file = process_get_file(fd);
	if(find_file ==NULL){
		return -1;
	}else{
		file_length(find_file);
	}
}

/* 열린 파일의 데이터를 읽는 시스템 콜
성공 시 읽은 바이트 수를 반환, 실패 시 -1 반환
fd 값이 0일 때 키보드의 데이터를 읽어 버퍼에 저장
 */
int
read (int fd, void *buffer, unsigned size) {
	check_address(buffer);
	int file_size;
	char *read_buffer = buffer;
	if(fd ==0){
		char key;
		 for(file_size = 0; file_size< size; file_size++){
			key = input_getc();
			*read_buffer++ = key;
			if(key =='\0'){
				break;
			}
		 }
	}else if(fd ==1){
		return -1;
	}else{
		struct file *read_file = process_get_file(fd);
		if(read_file ==NULL){
			return -1;
		}
		lock_acquire(&filesys_lock);
		file_size = file_read(read_file,buffer,size);
		lock_release(&filesys_lock);
	}
	return file_size;
}

/* 열린 파일의 데이터를 기록 시스템 콜
성공 시 기록한 데이터의 바이트 수를 반환, 실패시 -1 반환
fd 값이 1일 때 버퍼에 저장된 데이터를 화면에 출력. 
 */
int
write (int fd, const void *buffer, unsigned size) {
	int file_size;
	if(fd ==STDOUT_FILENO){
		putbuf(buffer, size);
		file_size = size;
	} else if(fd == STDIN_FILENO){
		return -1;
	} else{
		lock_acquire(&filesys_lock);
		file_size = file_write(process_get_file(fd), buffer, size);
		lock_release(&filesys_lock);
	}
	return file_size;
}

/* 열린 파일의 위치(offset)를 이동하는 시스템 콜 */
void
seek (int fd, unsigned position) {
	struct file *seek_file = process_get_file(fd);
	if(fd<=2){
		return ;
	}
	return file_seek(seek_file, position);
}

/* 열린 파일의 위치(offset)를 알려주는 시스템 콜 */
unsigned
tell (int fd) {
	struct file *tell_file = process_get_file(fd);
	return file_tell(tell_file);
}

/* 열린 파일을 닫는 시스템 콜
파일 식별자 fd를 닫습니다. 프로세스를 나가거나 종료하는 것은 묵시적으로 그 프로세스의 열려있는 파일 식별자들을 닫습니다.
마치 각 파일 식별자에 대해 이 함수가 호출된 것과 같습니다.
 */
void
close (int fd) {
	struct file *close_file = process_get_file(fd);
	if(close_file ==NULL){
		return -1;
	}
	process_close_file(fd);
	return file_close(close_file);
}


/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
    // TODO: Your implementation goes here.
	int number = f->R.rax;
    switch (number)
    {
    case SYS_HALT:
        halt();
		break;

    case SYS_EXIT:
        exit(f->R.rdi);
		break;

    case SYS_FORK:
        fork(f->R.rdi);
		break;

    case SYS_EXEC:
        exec(f->R.rdi);
		break;

    case SYS_WAIT:
        wait(f->R.rdi);
		break;

    case SYS_CREATE:
        create(f->R.rdi,f->R.rsi);
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
        read(f->R.rdi,f->R.rsi,f->R.rdx);
		break;

    case SYS_WRITE:
        write(f->R.rdi,f->R.rsi,f->R.rdx);
		break;

    case SYS_SEEK:
        seek(f->R.rdi,f->R.rsi);
		break;

    case SYS_TELL:
        tell(f->R.rdi);
		break;

    case SYS_CLOSE:
        close(f->R.rdi);
		break;

    default:
        break;
    }

}



