#include "userprog/syscall.h"
#include "../lib/user/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/inode.h"
#include "filesys/file.h"
#include "devices/shutdown.h"
#include <string.h>
#include "filesys/filesys.h"
#include "userprog/pagedir.h"
#include "devices/input.h"

#include "threads/synch.h"
#include "threads/palloc.h"

#include "userprog/process.h"

static void syscall_handler (struct intr_frame *);

static bool is_valid_pointer(const void *ptr);
static void valid_or_exit(const void* ptr, struct intr_frame *f);

void release_locks(void);

// system calls
static void sys_exit (int status, struct intr_frame *f); 
static pid_t sys_exec(const char *cmd_line);
static int sys_wait(pid_t pid);
static bool sys_create(const char *file, unsigned size);
static bool sys_remove(const char *file);
static int sys_open(const char *file);
static int sys_filesize(int fd);
static int sys_read(int fd, void *buffer, unsigned size);
static int sys_write(int fd, const void *buffer, unsigned size);
static void sys_seek(int fd, unsigned position);
static unsigned sys_tell(int fd);
static void sys_close(int fd);


/* Lock used for reading and writing from files. */
static struct lock read_write_lock;

void
syscall_init (void) 
{
	lock_init(&read_write_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
	char * sp  = f->esp;

	if(is_valid_pointer(sp)) 
		{
			int syscall_number = (int)*sp;
			sp += 4;
			switch(syscall_number)
				{
					char * file;
					void * buffer;
					unsigned int size;
					int fd;

					case SYS_HALT:   
						shutdown_power_off();
						break;

					case SYS_EXIT:       
						valid_or_exit(sp, f);
						int status;
						memcpy(&status,sp, 4);
						sys_exit(status, f);
						break; 
					
					case SYS_EXEC: 
						memcpy(&file,sp, 4);
						valid_or_exit(file, f);
						
						f->eax = sys_exec(file);
						break;     

					case SYS_WAIT:  
						valid_or_exit(sp, f);
						pid_t pid; 
						memcpy(&pid, sp, 4);
						f->eax = sys_wait(pid);
						break;   
					          
					case SYS_CREATE:      
						valid_or_exit(sp, f);
						memcpy(&file,sp, 4);
						valid_or_exit(file, f);
						sp += 4; 
						valid_or_exit(sp, f);
						memcpy(&size, sp, 4);
						f->eax = sys_create(file, size);
						break;       

					case SYS_REMOVE:      
						valid_or_exit(sp, f);
						memcpy(&file,sp, 4);
						f->eax = sys_remove(file);
						break;  

					case SYS_OPEN:    
						valid_or_exit(sp, f);
						memcpy(&file,sp, 4);
						valid_or_exit(file, f);
						f->eax = sys_open(file);
						break; 

					case SYS_FILESIZE:  
						valid_or_exit(sp, f);
						memcpy(&fd, sp, 4);
						f->eax = sys_filesize(fd);
						break;  

					case SYS_READ:    
						valid_or_exit(sp, f);
						memcpy(&fd,sp, 4); 
						sp += 4;
						valid_or_exit(sp, f);
						memcpy(&buffer,sp, 4);
						valid_or_exit(buffer, f);
						sp += 4;
						valid_or_exit(sp, f);
						memcpy(&size, sp, 4);
						lock_acquire(&read_write_lock);
						f->eax = sys_read(fd,buffer,size);
						lock_release(&read_write_lock);
						break; 

					case SYS_WRITE:
						valid_or_exit(sp, f);
						memcpy(&fd,sp, 4); 
						sp += 4;
						valid_or_exit(sp, f);
						memcpy(&buffer,sp, 4);
						sp += 4;
						valid_or_exit(sp, f);
						memcpy(&size,sp, 4);
						lock_acquire(&read_write_lock);
						f->eax = sys_write(fd,buffer,size);
						lock_release(&read_write_lock);
						valid_or_exit(buffer, f);
						break;  

					case SYS_SEEK: 
						valid_or_exit(sp, f);
						memcpy(&fd,sp, 4); 
						sp += 4;
						valid_or_exit(sp, f);
						unsigned int position;
						memcpy(&position, sp, 4);
						sys_seek(fd,position);
						break;   

					case SYS_TELL:           
						valid_or_exit(sp, f);
						memcpy(&fd,sp, 4); 
						f->eax = sys_tell(fd);
						break;    

					case SYS_CLOSE:  
						valid_or_exit(sp, f);
						memcpy(&fd,sp, 4); 
						sys_close(fd);
						break;

					default:
						
						break;           
				}
		}
	
	else
		{
			sys_exit(-1, f);
		}
}

// helper method that determines if the pointer is valid
static bool
is_valid_pointer(const void* ptr)
{
	struct thread * cur = thread_current ();
	if((ptr != NULL) && is_user_vaddr(ptr) && (pagedir_get_page(cur->pagedir,ptr) != NULL)) 
	{
		return true;
	}
	return false;
}

// helper method that determines if the pointer is valid
// if this method returns, the pointer was valid; otherwise, the process exits with status -1
static void
valid_or_exit(const void* ptr, struct intr_frame *f)
{
		if(!is_valid_pointer(ptr))
	{
		sys_exit(-1,f);
	}
}

/*releases the read_write_lock if the current thread has it */
void
release_locks()
{
	if(lock_held_by_current_thread (&read_write_lock))
		lock_release(&read_write_lock);
}

/*System exit handler, sets exit_status, frees locks,
  closes files, and waits to be reaped if it is a child
  before calling thread_exit()*/
static void 
sys_exit (int status, struct intr_frame *f)
{

	f->eax = status;
	struct thread * current_thread = thread_current ();
	struct thread * parent_thread = current_thread->parent;
	current_thread->exit_status = status;

	//release lock(s)
	release_locks();

	//close all open files for this process
	int i;
	for(i = 2; i < 130; i++)
	{
		struct file * f = current_thread->files[i];
		if(f!=NULL)
		{
			file_close(f);
		}
	}
	
	file_allow_write(current_thread->executable_file);
	
	char * save_ptr;
  char * name_without_args = strtok_r (current_thread->name, " ", &save_ptr);
	printf ("%s: exit(%d)\n", name_without_args, status);
	if(parent_thread!=NULL)
	{
		sema_up(&(current_thread->exit_sema)); // signals that our exit status is ready to be reaped
		sema_down(&(parent_thread->reap_sema)); // we wait to be reaped
	}
	
	thread_exit ();
}

/*Executes the process in cmd_line, and waits for the child to complete loading before continuing. */
static pid_t
sys_exec(const char *cmd_line) 
{

	tid_t child_id = process_execute(cmd_line);
	
	struct thread * child_thread = get_thread(child_id);
	
	if(child_id!=TID_ERROR)
	{
		
		sema_down(&(child_thread->parent_sema));
	}
	if(child_thread->exit_status < 0)
		return -1;
	

	return child_id;
}

/*calls process_wait, all checks are done in process_wait.
  If some kind of error occurs then it returns -1*/
static int
sys_wait(pid_t pid) 
{
	return process_wait(pid);
}

/*creates the file with name "file" and size
  "size" by calling a filesys method*/
static bool
sys_create(const char * file, unsigned size)
{
	bool result = filesys_create(file, size);	

	return result;
}

/*removes file by calling filesys method*/
static bool
sys_remove(const char * file) 
{
	if(is_valid_pointer(file))
	{
		return filesys_remove (file);
	}
	return false;
}

/*opens file using filesys method and adds a pointer
  of the file to files[] based on what fd number is chosen
  for it, returns fd, or -1 if unsuccessful or if no more
  files can be opened*/
static int
sys_open(const char * file) 
{
	if(is_valid_pointer(file))
	{
		struct thread * current_thread = thread_current ();
		if(current_thread->num_open_files < 130)
		{
			struct file * f = filesys_open(file);
			if(f!=NULL)
			{
				struct file ** files = current_thread->files;
				int i;
				for(i = 2; i < 130; i++)
				{
					if(files[i]==NULL)
					{
						files[i] = f;
						current_thread->num_open_files = current_thread->num_open_files + 1;
						return i;
					}
				}
			}
		}
	}
	return -1;
}

/*returns file size of fd, uses file and idnode methods
  to get the size of the file*/
static int
sys_filesize(int fd) 
{
	if(fd >= 2 && fd < 130)
	{
		struct thread * current_thread = thread_current ();
		struct file * f = current_thread->files[fd];
		if(f != NULL)
		{
			struct inode * inode = file_get_inode(f);
			int size = inode_length(inode);
			return size;
		}
	}
	return 0;
}

/*Reads from console if fd == 0 or from a file
  opened by the process if fd >= 2*/
static int
sys_read(int fd, void *buffer, unsigned size) 
{
	unsigned int bytes_read = 0;
	char * char_buffer = (char *)buffer;
	if(is_valid_pointer(buffer) && fd >= 0 && fd < 130)
		{

			if(fd==0) // read from keyboard
				{
					while(bytes_read < size)
						{
							char c = input_getc();
							*char_buffer = c;
							char_buffer++;
							bytes_read++;
						}
					return bytes_read;
				}
			else if(fd > 1)// read from open files
			{
				struct file * f = thread_current()->files[fd];
				if(f!=NULL)
				{
					return file_read(f,buffer,size);
				}
			}
		}
	return -1;
}

/*Writes to console if fd == 1 or to a file
  opened by the process if fd >= 2*/
static int
sys_write(int fd, const void *buffer, unsigned size) 
{
	if(is_valid_pointer(buffer) && fd >= 0 && fd < 130 )
		{	
	
			if(fd==1) // write to console
				{
					int remaining = size;
					while(remaining > 200)
						{
							putbuf(buffer,200);
							remaining -= 200;
							buffer += 200;
						}
	
					putbuf(buffer,remaining);
			
					return size;
				}
			else if(fd > 1)//read from open files
			{
				struct file * f = thread_current()->files[fd];
				if(f!=NULL)
				{
					return file_write(f,buffer,size); 
				}
			}
		}
	return 0;
}

/*uses file method to seek to position in fd*/
static void
sys_seek(int fd, unsigned position) 
{
	if(fd >= 2 && fd < 130)
	{
		struct file * f = thread_current()->files[fd];
		if(f!=NULL)
		{
			file_seek(f,position);
		}
	}
}

/*uses file method to tell the position in fd*/
static unsigned
sys_tell(int fd) 
{
	if(fd >= 2 && fd < 130)
	{
		struct file * f = thread_current()->files[fd];
		if(f!=NULL)
		{
			return file_tell(f);
		}
	}
	return 0;
}

/*closes the file, removing it from the process*/
static void
sys_close(int fd) 
{
	if(fd >= 2 && fd < 130)
	{
		struct file * f = thread_current()->files[fd];
		if(f!=NULL)
		{
			thread_current()->files[fd] = NULL;
			file_close(f);
		}
	}
}

