#ifndef FS_TRACELOG_H
#define FS_TRACELOG_H

#include <linux/sched.h>
#include <linux/fs_struct.h>

/* Is tracelog enabled? */
extern volatile int fs_tracelog_flag;
static inline int fs_tracelog_enabled(void) {
	int result;
	if (fs_tracelog_flag) {
		task_lock(current);
		result = current->fs->logging;
		task_unlock(current);
		return result;
	} else return 0;
}
int fs_tracelog_add(size_t count, char** msg);

#endif
