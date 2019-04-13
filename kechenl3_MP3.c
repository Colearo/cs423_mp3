#define LINUX

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/proc_fs.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/mm.h>
#include <asm/uaccess.h>
#include "mp3_given.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kechen Lu");
MODULE_DESCRIPTION("CS-423 MP3 Page Fault Profiler");

#define DEBUG 1

// Declare all needed global variables for the proc fs initializaiton
// The mp3 directory
#define MP3_DIR "mp3"
struct proc_dir_entry * mp3_dir;
// The mp3/status entry
#define MP3_STAT "status"
struct proc_dir_entry * mp3_status;

#define MONITOR_CHRDEV "mp3_chrdev"
// Dynamically create character device
unsigned int chrdev_major = 0;

#define NPAGES 128

// Kernel slab cache allocator
struct kmem_cache *tasks_cache;

// Spinlock
spinlock_t sl;

// mapped buffer
unsigned long* mapped;
// mapped buffer offset
unsigned long mapped_offset = 0;

// Define the customized task struct, which contains process utilization
// and major and minor page fault counts
struct mp3_task_struct {
    struct list_head next;
    unsigned int pid;

    unsigned long utilization;
    unsigned long major_page_fault;
    unsigned long minor_page_fault;
};

// Define the tasks list
LIST_HEAD(reg_task_list);

// Parser helper function to get next phrase between comma
char* parse_next_phrase(char **str) {
    char *res, *p;
    res = kmalloc(128 * sizeof(char), GFP_KERNEL);
    memset(res, 0, 128 * sizeof(char));
    p = res;

    if (*str == NULL) {
	kfree(res);
	return NULL;
    }

    while(*(*str) != 0) {
	*(p++) = *((*str)++);
	if (*(*str) == ' ') {
	    (*str)++;
	    break;
	}
    }

    return res;
}

#define MAX_BUF_SIZE 4096
// Declare the workqueue pointer
static struct workqueue_struct *wq;
// Declare the work handler
static void work_handler(struct work_struct *work_arg);
// Define the workqueue name
#define MONITOR_WQ "monitor_wq"
// Declare the delayed work
DECLARE_DELAYED_WORK(monitor_work, work_handler);

// Wrapper for work function without lock
static void _work_handler(void) {
    struct mp3_task_struct *cur, *temp;
    unsigned long min_flt, maj_flt, utime, stime;
    unsigned long sum_min_flt = 0, sum_maj_flt = 0, sum_util = 0;
    int ret;

    // Iterate the whole linked list to update each registered process
    list_for_each_entry_safe(cur, temp, &reg_task_list, next) {
	// Get the task PCB corresponding information by PID
	ret = get_cpu_use((int)cur->pid, &min_flt, 
		&maj_flt, &utime, &stime);
	if (ret != 0) {
	   list_del(&cur->next);
	   kfree(cur);
	} else {
	    cur->utilization = utime + stime;
	    cur->major_page_fault = maj_flt;
	    cur->minor_page_fault = min_flt;
	}
    }

    // Iterate the whole linked list to get the sum of the 
    // utilization time, major page fault count and minor
    // page fault count
    list_for_each_entry_safe(cur, temp, &reg_task_list, next) {
	// Get the task PCB corresponding information by PID
	sum_util += cur->utilization;
	sum_min_flt += cur->minor_page_fault;
	sum_maj_flt += cur->major_page_fault;
    }
    
    // Copy to the mapped buffer
    *(mapped + mapped_offset++) = jiffies;
    *(mapped + mapped_offset++) = sum_min_flt;
    *(mapped + mapped_offset++) = sum_maj_flt;
    *(mapped + mapped_offset++) = sum_util;
}

// Work function for workqueue to be scheduled
// periodically measures the major and minor page fault 
// counts, and CPU utilization
static void work_handler(struct work_struct *work_arg) {
    unsigned long flags;

    // Spinlock lock
    spin_lock_irqsave(&sl, flags);

    // Wraper func
    _work_handler();

    // Spinlock unlock
    spin_unlock_irqrestore(&sl, flags);

    // Queue next monitor work
    queue_delayed_work(wq, &monitor_work, msecs_to_jiffies(50));

    printk(KERN_DEBUG "Workqueue worker completed\n");
}

// Registration func for process to register
static ssize_t registration(unsigned int pid) {
    struct mp3_task_struct *task_ptr;
    struct mp3_task_struct *cur, *temp;
    unsigned long flags, min_flt, maj_flt, utime, stime;
    int ret, size = 0;

    // Get the task PCB corresponding information by PID
    ret = get_cpu_use((int)pid, &min_flt, 
	    &maj_flt, &utime, &stime);
    if (ret == -1) 
	return -EFAULT;

    // Allocate the corresponding struct using slab cache allocator
    task_ptr = kmem_cache_alloc(tasks_cache, GFP_KERNEL);

    // Assign the pid and other information of this task to the task structure
    task_ptr->pid = pid;
    task_ptr->utilization = utime + stime;
    task_ptr->major_page_fault = maj_flt;
    task_ptr->minor_page_fault = min_flt;

    // Linked list entry
    INIT_LIST_HEAD(&task_ptr->next);

    // Spinlock lock
    spin_lock_irqsave(&sl, flags);
    // Add the task to the registartion task list
    list_add(&task_ptr->next, &reg_task_list);
    // If the first task added, 
    list_for_each_entry_safe(cur, temp, &reg_task_list, next) {
	size++;
    }

    // If the first one, clean the mapped memory and queue dwork
    if (size == 1) {
	memset(mapped, 0, NPAGES * PAGE_SIZE);
	queue_delayed_work(wq, &monitor_work, msecs_to_jiffies(50));
    }

    // Spinlock unlock
    spin_unlock_irqrestore(&sl, flags);

    return 0;
}

// Unregistration not holding the lock
static void __unregistration(unsigned int pid, int* flag) {
    struct mp3_task_struct *cur, *temp;
    int size = 0;

    // Iterate the whole linked list to delete the PID equals this pid
    list_for_each_entry_safe(cur, temp, &reg_task_list, next) {
	// Calculate the size
	size++;

	// If the current task's pid is the one we want, delete it
	if (cur->pid == pid) {
	    *flag = 1;
	    // Delete the node of this linked list
	    list_del(&cur->next);
	    // Free the slab cache
	    kmem_cache_free(tasks_cache, cur);
	}
    }

    // If the last one deleted, terminate the work job
    if (size == 1) {
	if (!cancel_delayed_work_sync(&monitor_work))
	    cancel_delayed_work_sync(&monitor_work);
	mapped_offset = 0;
    }
}

// Unregistration for the tasks by pid
static ssize_t unregistration(unsigned int pid) {
    int flag = 0;
    unsigned long flags;

    // Spinlock lock
    spin_lock_irqsave(&sl, flags);

    // Deregistration to de-allocate and clean the related resources
    __unregistration(pid, &flag);
    
    // Spinlock unlock
    spin_unlock_irqrestore(&sl, flags);

    if (flag == 0) 
	return -EFAULT;

    return 0;
}


// Decalre the callback functions for proc read and write
// Write callback function for user space to write pid to the 
// /proc/mp3/status file
ssize_t write_call(struct file *file, 
	const char __user *usr_buf, 
	size_t n, 
	loff_t *ppos) {
    // Local variable to store the result copied from user buffer
    char *kern_buf, *token, *head;
    // Variables used in the kstrtoul()
    unsigned long pid_val;
    int ret = 0;

    // Using vmalloc() to allocate buffer for kernel space
    kern_buf = (char *)kmalloc(MAX_BUF_SIZE * sizeof(char), GFP_KERNEL);
    if (!kern_buf) 
	return -ENOMEM;
    memset(kern_buf, 0, MAX_BUF_SIZE * sizeof(char));
    head = kern_buf;

    // If the input str is larger than buffer, return error
    if (n > MAX_BUF_SIZE || *ppos > 0) {
	ret = -EFAULT;
	goto RET;
    }

    if (copy_from_user(kern_buf, usr_buf, n)) {
	ret = -EFAULT;
	goto RET;
    }

    kern_buf[n] = 0;
    printk(KERN_DEBUG "ECHO %s", kern_buf); 

    if (n < 3) {
	printk(KERN_ALERT "Incorrect format to have the commands\n");
	ret = -EFAULT;
	goto RET;
    }

    switch(kern_buf[0]) {
	case 'R' :
	    printk(KERN_DEBUG "REGISTRATION\n");

	    kern_buf += 2;
	    token = parse_next_phrase(&kern_buf);
	    // Convert the pid string to the integer type
	    ret = kstrtoul(token, 10, &pid_val);
	    kfree(token);
	    if (ret != 0) 
		goto RET;
	    printk(KERN_DEBUG "PID: [%d]\n", (int)pid_val);

	    // REGISTRATION for the new task
	    ret = registration(pid_val);
	    if (ret != 0)
		goto RET;

	    break;

	case 'U' :
	    printk(KERN_DEBUG "UNREGISTRATION\n");

	    kern_buf += 2;
	    token = parse_next_phrase(&kern_buf);
	    // Convert the pid string to the integer type
	    ret = kstrtoul(token, 10, &pid_val);
	    kfree(token);
	    if (ret != 0) 
		goto RET;
	    printk(KERN_DEBUG "PID: [%d]\n", (int)pid_val);

	    // Do the YIELD for relinquishing the CPU control
	    ret = unregistration(pid_val);
	    if (ret != 0)
		goto RET;

	    break;

	default :
	    printk(KERN_DEBUG "NO MATCHED\n");
	    ret = -EFAULT;
	    goto RET;
    }

    ret = n;

RET: kfree(head);
     return ret;
}


// Read callback function for user space to read the proc file in
// /proc/mp3/status
ssize_t read_call(struct file *file, 
	char __user *usr_buf, 
	size_t n, 
	loff_t *ppos) {
    // Local variable to store the data would copy to user buffer
    char* kern_buf;
    int length = 0;
    unsigned long flags;
    struct mp3_task_struct *cur, *temp;

    // Using kmalloc() to allocate buffer for kernel space
    kern_buf = (char *)kmalloc(MAX_BUF_SIZE * sizeof(char), GFP_KERNEL);
    if (!kern_buf) 
	return -ENOMEM;
    memset(kern_buf, 0, MAX_BUF_SIZE * sizeof(char));

    // If the input str is larger than buffer or 
    // someone has read it to let offset pointer is not to 0, return zero
    if (n < MAX_BUF_SIZE || *ppos > 0) {
	kfree(kern_buf);
	return 0;
    }

    spin_lock_irqsave(&sl, flags);
    list_for_each_entry_safe(cur, temp, &reg_task_list, next) {
	// Iterate the list to cat the information of each managed task
	length += sprintf(kern_buf + length, "%u\n", cur->pid);
    }
    spin_unlock_irqrestore(&sl, flags);

    // If no pid registered in list
    if (length == 0) {
	kfree(kern_buf);
	length = sprintf(kern_buf, "No PID registered\n");
    }

    printk(KERN_DEBUG "Read this proc file %d\n", length);
    kern_buf[length] = 0;

    // Copy returned data from kernel space to user space
    if (copy_to_user(usr_buf, (const void *)kern_buf, length)) {
	kfree(kern_buf);
	return -EFAULT;
    }
    *ppos = length;

    kfree(kern_buf);
    return length;
}

// File operations callback functions, overload read, write, open, and 
// so forth a series of ops
static const struct file_operations mp3_proc_fops = {
    .owner = THIS_MODULE,
    .write = write_call,
    .read = read_call,
};

// Monitor character device open
static int monitor_open(struct inode *inode, struct file *filp) {
    return 0;
}

// Monitor character device close
static int monitor_close(struct inode *inode, struct file *filp) {
    return 0;
}

// Monitor character device mmap
static int monitor_mmap(struct file *filp, struct vm_area_struct *vma) {
    unsigned long len, pfn, offset;
    int ret;
    len = vma->vm_end - vma->vm_start;

    for (offset = 0; offset < len; offset += PAGE_SIZE) {
	pfn = vmalloc_to_pfn((void *)((unsigned long)mapped + offset));
	ret = remap_pfn_range(vma, vma->vm_start + offset, pfn, 
		PAGE_SIZE, vma->vm_page_prot);
	if (ret < 0) {
	    printk(KERN_ERR "could not map the vmlloc address page\n");
	    return -EIO;
	}
    }
    return 0;
}

// Character device operation options
static const struct file_operations mp3_chrdev_fops = {
    .owner = THIS_MODULE,
    .open = monitor_open,
    .release = monitor_close,
    .mmap = monitor_mmap
};

// mp3_init - Called when module is loaded
int __init mp3_init(void) {
    int ret;
    unsigned long i;

#ifdef DEBUG
    printk(KERN_ALERT "MP3 MODULE LOADING\n");
#endif
    // Make a new proc dir /proc/mp1
    mp3_dir = proc_mkdir(MP3_DIR, NULL); 
    // Make a new proc entry /proc/mp1/status
    mp3_status = proc_create(MP3_STAT, 0666, mp3_dir, &mp3_proc_fops); 

    // Create a character device
    ret = register_chrdev(chrdev_major, MONITOR_CHRDEV, &mp3_chrdev_fops);
    if (ret < 0) {
       printk(KERN_WARNING "Can't get major %d\n", chrdev_major);
       return ret;
    }
    chrdev_major = (unsigned int)ret;

    // Make a new slab cache
    tasks_cache = KMEM_CACHE(mp3_task_struct, SLAB_PANIC);

    // Allocate the vmalloc buffer in size 128 * 4KB
    mapped = (unsigned long*)vmalloc(NPAGES * PAGE_SIZE);
    // Set the page reversed bit
    for(i = 0; i < NPAGES * PAGE_SIZE; i += PAGE_SIZE) {
	SetPageReserved(vmalloc_to_page((void *)((unsigned long)mapped + i)));
    }

    // Initialize a new workqueue
    wq = alloc_workqueue(MONITOR_WQ, WQ_MEM_RECLAIM, 0);

    // Make a new spinlock for sychronization
    spin_lock_init(&sl);

    printk(KERN_ALERT "MP3 MODULE LOADED\n");
    return 0;   
}

// mp3_exit - Called when module is unloaded
void __exit mp3_exit(void) {
    struct mp3_task_struct *cur, *temp;
    unsigned long i;

#ifdef DEBUG
    printk(KERN_ALERT "MP3 MODULE UNLOADING\n");
#endif

    // Remove all the proc file entry and dir we created before
    proc_remove(mp3_status);
    proc_remove(mp3_dir);

    // Destroy the workqueue
    if (wq != NULL) {
       if (!cancel_delayed_work_sync(&monitor_work))
	   cancel_delayed_work_sync(&monitor_work);
       destroy_workqueue(wq);
    }

    //Iterate the whole linked list to delete the PID equals this pid
    list_for_each_entry_safe(cur, temp, &reg_task_list, next) {
	    list_del(&cur->next);
	    kmem_cache_free(tasks_cache, cur);
    }

    unregister_chrdev(chrdev_major, MONITOR_CHRDEV);

    // Clear the page reversed bit and then vfree
    for(i = 0; i < NPAGES * PAGE_SIZE; i += PAGE_SIZE) {
	ClearPageReserved(vmalloc_to_page((void *)((unsigned long)mapped + i)));
    }
    vfree(mapped);

    kmem_cache_destroy(tasks_cache);

    printk(KERN_ALERT "MP3 MODULE UNLOADED\n");
}

// Register init and exit funtions
module_init(mp3_init);
module_exit(mp3_exit);
