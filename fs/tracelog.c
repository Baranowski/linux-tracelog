#include <linux/slab.h> 
#include <linux/list.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/fs_struct.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <asm/current.h>

#include "tracelog.h"

#define FS_TRACELOG_LIMIT 1000;

struct fs_tracelog_t {
	struct list_head list;
	const char* msg;
};

/* Is tracelog enabled? */
volatile int fs_tracelog_flag;

static struct semaphore fs_tracelog_mutex;
static struct list_head fs_tracelog_list;
static unsigned long fs_tracelog_next_id = 0;
static int fs_tracelog_size = 0;
static int fs_tracelog_limit = FS_TRACELOG_LIMIT;

static int fstlcache_dirty;
static loff_t fstlcache_pos;
static void * fstlcache_v;

/* Remove how_many log messages (or all of them if how_many is greater).
 * Called within critical section
 */
static void fs_tracelog_rm(int how_many)
{
	struct list_head *prev, *iterator = fs_tracelog_list.prev;
	struct fs_tracelog_t *entry;
	for (; how_many > 0 && iterator != &fs_tracelog_list; --how_many) {
		prev = iterator->prev;
		list_del(iterator);
		entry = list_entry(iterator, struct fs_tracelog_t, list);
		kfree(entry->msg);
		kfree(entry);
		--fs_tracelog_size;
		iterator = prev;
	}

	if (fs_tracelog_size <= fstlcache_pos)
		fstlcache_dirty = 1;
}

/* Add header to the messages and insert as new log lines.
 * Returns one of: 0, -ENOMEM, -ERESTARTSYS
 */
int fs_tracelog_add(size_t count, char** msgs) {
	struct fs_tracelog_t *new_entry;
	struct list_head new_lines, *list_it, *tmp;
	unsigned long orig_next_id;
	size_t i;
	int ret = 0;

	INIT_LIST_HEAD(&new_lines);

	if (down_interruptible(&fs_tracelog_mutex))
		return -ERESTARTSYS;

		orig_next_id = fs_tracelog_next_id;

		for (i = 0; !ret && i < count; ++i) {
			new_entry = kmalloc(sizeof(struct fs_tracelog_t), GFP_KERNEL);
			if (!new_entry) {
				ret = -ENOMEM;
				goto cleanup;
			}
			new_entry->msg = kasprintf(GFP_KERNEL, "%lu %d %d %u %s\n",
				fs_tracelog_next_id++, current->pid, current->real_cred->uid,
				jiffies_to_msecs((unsigned long)get_jiffies_64()), msgs[i]);
			if (!new_entry->msg) {
				kfree(new_entry);
				ret = -ENOMEM;
				goto cleanup;
			}
			list_add(&new_entry->list, &new_lines);
		}

		fstlcache_pos += count;
		list_splice(&new_lines, &fs_tracelog_list);
		fs_tracelog_size += count;
		if (fs_tracelog_size > fs_tracelog_limit)
			fs_tracelog_rm(fs_tracelog_size - fs_tracelog_limit);

	up(&fs_tracelog_mutex);

	return 0;

	cleanup:
        list_for_each_safe(list_it, tmp, &new_lines) { // Czyscimy liste
            new_entry = list_entry(list_it, struct fs_tracelog_t, list);
            kfree(new_entry->msg);
            list_del(&new_entry->list);
            kfree(new_entry);
        }
		fs_tracelog_next_id = orig_next_id;
		up(&fs_tracelog_mutex);
		return ret;
}
EXPORT_SYMBOL(fs_tracelog_add);

static void *fs_tracelog_log_seq_start(struct seq_file *s, loff_t *pos)
{
	loff_t i;
	loff_t dist;
	struct list_head *iterator;
	unsigned long fixed_pos;
	if (down_interruptible(&fs_tracelog_mutex))
		return ERR_PTR(-ERESTARTSYS);
	
	fixed_pos = *pos + fs_tracelog_next_id - *(unsigned long *)s->private;

	if (fixed_pos >= fs_tracelog_size)
		return NULL;

	/* Choose the list item closest to the destination from among:
	 * front of the list, end of the list and pointer in cache.
	 */
	if (fixed_pos < fs_tracelog_size-1 - fixed_pos) {
		i = 0;
		iterator = fs_tracelog_list.next;
		dist = fixed_pos;
	} else {
		i = fs_tracelog_size-1;
		iterator = fs_tracelog_list.prev;
		dist = i-fixed_pos;
	}
	if (!fstlcache_dirty) {
		if ((fstlcache_pos <= fixed_pos && fixed_pos - fstlcache_pos < dist) ||
			(fstlcache_pos > fixed_pos && fstlcache_pos - fixed_pos < dist))
		{
			i = fstlcache_pos;
			iterator = fstlcache_v;
		}
	} /* dist no longer used below */
	/* Walk to the destination */
	while (i < fixed_pos) {
		iterator = iterator->next;
		++i;
	}
	while (i > fixed_pos) {
		iterator = iterator->prev;
		--i;
	}

	return iterator;
}

static void fs_tracelog_log_seq_stop(struct seq_file *s, void *v)
{
	if (!IS_ERR(v)) {
		up(&fs_tracelog_mutex);
	}
}

static int fs_tracelog_log_seq_show(struct seq_file *s, void *v)
{
	struct list_head *iterator;
	if (!IS_ERR_OR_NULL(v)) {
		iterator = (struct list_head *)v;
		seq_puts(s, list_entry(v, struct fs_tracelog_t, list)->msg);
	}
	return 0;
}

static void *fs_tracelog_log_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	struct list_head *iterator = (struct list_head *)v;
	iterator = iterator->next;
	++*pos;
	if (iterator == &fs_tracelog_list)
		iterator = NULL;
	fstlcache_pos = *pos + fs_tracelog_next_id - *(unsigned long *)s->private;
	fstlcache_v = iterator;
	fstlcache_dirty = 0;

	return iterator;
}

static struct seq_operations fs_tracelog_log_seq_ops = {
		.start = fs_tracelog_log_seq_start,
		.next  = fs_tracelog_log_seq_next,
		.stop  = fs_tracelog_log_seq_stop,
		.show  = fs_tracelog_log_seq_show,
};

static int fs_tracelog_log_open(struct inode *inode, struct file *file)
{
		int ret;
		unsigned long *private;
		struct seq_file *seq;
		private = kmalloc(sizeof(unsigned long), GFP_KERNEL);
		if (!private)
			return -ENOMEM;
		if (down_interruptible(&fs_tracelog_mutex)) {
			kfree(private);
			return -ERESTARTSYS;
		}
		*private = fs_tracelog_next_id;
		up(&fs_tracelog_mutex);
		ret = seq_open(file, &fs_tracelog_log_seq_ops);
		if (ret) {
			kfree(private);
			return ret;
		}
		seq = file->private_data;
		seq->private = private;
		return ret;
};

static struct file_operations fs_tracelog_log_fops = {
		.open    = fs_tracelog_log_open,
		.read    = seq_read,
		.llseek  = seq_lseek,
		.release = seq_release_private
};

/* Helper function for accepting single character from user.
 * Returns character read or negative error code
 */
static int fs_tracelog_input_char(const char __user *buf, size_t count)
{
	char local_buff[2]; // max length is 1 char + '\n'

	if (count == 0 || count > sizeof(local_buff))
		return -EINVAL;
	if (copy_from_user(local_buff, buf, count))
		return -EFAULT;
	if (count > 1 && local_buff[1] != '\n')
		return -EINVAL;
	return local_buff[0];
}

static ssize_t proc_tracelog_clear_write(struct file *file,
					  const char __user *buf,
					  size_t count,
					  loff_t *ppos)
{
	int chr = fs_tracelog_input_char(buf, count);
	if (chr < 0)
		return chr;
	if (chr != '1')
		return -EINVAL;

	if (down_interruptible(&fs_tracelog_mutex))
		return -ERESTARTSYS;
	fs_tracelog_rm(fs_tracelog_size);
	up(&fs_tracelog_mutex);

	return count;
}

static struct file_operations fs_tracelog_clear_fops = {
		.write   = proc_tracelog_clear_write,
};

static ssize_t proc_tracelog_enabled_write(struct file *file,
					  const char __user *buf,
					  size_t count,
					  loff_t *ppos)
{
	int chr = fs_tracelog_input_char(buf, count);
	if (chr < 0)
		return chr;
	if (chr < '0' || chr > '1')
		return -EINVAL;

	fs_tracelog_flag = chr - '0';
	return count;
}

static struct file_operations fs_tracelog_enabled_fops = {
		.write   = proc_tracelog_enabled_write,
};

/* Helper function for accepting single integer from user.
 * Returns integer received or negative error code.
 */
static int fs_tracelog_input_uint(const char __user *buf, size_t count)
{
	unsigned long input;
	char *local_buf = kmalloc(count + 1, GFP_KERNEL);
	if (!local_buf)
		return -ENOMEM;
	if (copy_from_user(local_buf, buf, count)) {
		kfree(local_buf);
		return -EFAULT;
	}
	local_buf[count] = '\0';
	if (strict_strtoul(local_buf, 10, &input)) { // 10 - base for conversion
		kfree(local_buf);
		return -EINVAL;
	}
	kfree(local_buf);
	return input;
}

static ssize_t proc_tracelog_entry_limit_write(struct file *file,
					  const char __user *buf,
					  size_t count,
					  loff_t *ppos)
{
	int input = fs_tracelog_input_uint(buf, count);
	if (input < 0)
		return input;
	if (input == 0)
		return -EINVAL;
	if (down_interruptible(&fs_tracelog_mutex))
		return -ERESTARTSYS;
	fs_tracelog_limit = input;
	if (fs_tracelog_size > fs_tracelog_limit)
		fs_tracelog_rm(fs_tracelog_size - fs_tracelog_limit);
	up(&fs_tracelog_mutex);
	return count;
}

static struct file_operations fs_tracelog_entry_limit_fops = {
		.write   = proc_tracelog_entry_limit_write,
};

static ssize_t proc_tracelog_clear_last_write(struct file *file,
					  const char __user *buf,
					  size_t count,
					  loff_t *ppos)
{
	int input = fs_tracelog_input_uint(buf, count);
	if (input < 0)
		return input;
	if (down_interruptible(&fs_tracelog_mutex))
		return -ERESTARTSYS;
	fs_tracelog_rm(input);
	up(&fs_tracelog_mutex);
	return count;
}

static struct file_operations fs_tracelog_clear_last_fops = {
		.write   = proc_tracelog_clear_last_write,
};

static int __init fs_tracelog_init(void)
{
	struct proc_dir_entry *root_dir;
	struct proc_dir_entry *log_file, *clear_file, *enabled_file,
		*entry_limit_file, *clear_last_file;

	INIT_LIST_HEAD(&fs_tracelog_list);
	init_MUTEX(&fs_tracelog_mutex);

	fstlcache_dirty = 1;

	root_dir = proc_mkdir("tracelog", NULL);
	if (likely(root_dir)) {
		log_file = create_proc_entry("log", S_IRUSR, root_dir);
		if (log_file) {
			log_file->proc_fops = &fs_tracelog_log_fops;
		} else printk(KERN_ERR "fs_tracelog_init: error while creating log_file");

		clear_file = create_proc_entry("clear", S_IWUSR, root_dir);
		if (clear_file) {
			clear_file->proc_fops = &fs_tracelog_clear_fops;
		} else printk(KERN_ERR "fs_tracelog_init: error while creating clear_file");

		enabled_file = create_proc_entry("enabled", S_IWUSR, root_dir);
		if (enabled_file) {
			enabled_file->proc_fops = &fs_tracelog_enabled_fops;
		} else printk(KERN_ERR "fs_tracelog_init: error while creating enabled_file");

		entry_limit_file = create_proc_entry("entry_limit", S_IWUSR, root_dir);
		if (entry_limit_file) {
			entry_limit_file->proc_fops = &fs_tracelog_entry_limit_fops;
		} else printk(KERN_ERR "fs_tracelog_init: error while creating entry_limit_file");

		clear_last_file = create_proc_entry("clear_last", S_IWUSR, root_dir);
		if (clear_last_file) {
			clear_last_file->proc_fops = &fs_tracelog_clear_last_fops;
		} else printk(KERN_ERR "fs_tracelog_init: error while creating clear_last_file");
	} else printk(KERN_ERR "fs_tracelog_init: error while creating root_dir");
	return 0;
}
module_init(fs_tracelog_init);
