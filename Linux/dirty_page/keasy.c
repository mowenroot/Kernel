#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/file.h>
#include <linux/anon_inodes.h>

#include "keasy.h"

static struct chrdev_info cinfo = {};

ssize_t keasy_file_read(struct file *filp, char __user *buf, size_t sz, loff_t *off) {
	char msg[] = "🤓";
	(void)copy_to_user(buf, msg, sizeof(msg));
	return sizeof(msg);
}

const struct file_operations keasy_file_fops = {
	.owner = THIS_MODULE,
	.read = keasy_file_read
};

// 是否启动enabled
unsigned enabled = 1;

static long keasy_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
	// EINVAL是Linux内核中的一个错误代码，代表"Invalid argument"，即"无效的参数"。
	// 当系统调用或函数接收到一个无效或不合法的参数时，会返回EINVAL错误代码。
	long ret = -EINVAL;


	struct file *myfile;
	int fd;

	if (!enabled) {
		goto out;
	}
	enabled = 0;
	/*
	anon_inode_getfile函数是Linux内核中的一个函数，它负责创建一个匿名inode并将其与一个文件结构关联起来。
	这个函数主要用于在内核中创建没有对应磁盘文件的文件对象。
	当一个进程调用某些系统调用（如pipe或eventfd）需要创建一个没有对应磁盘文件的类似文件的对象时，
	就会调用anon_inode_getfile函数。它创建一个匿名inode并返回与之关联的文件对象。
	下面是anon_inode_getfile执行的大致步骤：
	该函数首先检查传递给它的struct file对象是否已经关联了一个inode。
	如果是，则返回错误，因为该函数仅用于创建匿名inode。
	然后，它分配一个新的struct inode对象，并将其设置为匿名inode。
	匿名inode是一个没有对应磁盘文件的inode。它用于表示各种内核特定的对象，例如管道或事件文件描述符。
	接下来，函数分配一个新的struct file对象，并用上一步创建的匿名inode进行初始化。
	函数使用适当的文件操作结构设置文件对象的f_op字段，该结构包含处理特定于正在创建的对象类型的文件相关操作的函数指针。
	最后，函数将新创建的文件对象返回给调用者。
	*/
    myfile = anon_inode_getfile("[easy]", &keasy_file_fops, NULL, 0);

	// 获取一样未使用的fd
    fd = get_unused_fd_flags(O_CLOEXEC);
    if (fd < 0) {
        ret = fd;
        goto err;
    }

	// 将fd安装到myfile
    fd_install(fd, myfile);

	// copy_to_user()是一种用于将内核空间中的数据复制到用户空间的函数。 它的返回值类型是unsigned long，
	// 通常用于指示复制的数据长度或者错误码。 
	// 当copy_to_user()函数成功复制了全部或部分数据到用户空间时，它会返回0。
	if (copy_to_user((unsigned int __user *)arg, &fd, sizeof(fd))) {
		ret = -EINVAL;
		goto err;
	}

	ret = 0;
    return ret;

err:
    fput(myfile);
out:
	return ret;
}

static int keasy_open(struct inode *inode, struct file *file) {
	return 0;
}

static int keasy_release(struct inode *inode, struct file *file) {
	return 0;
}

static struct file_operations keasy_fops = {
	.owner = THIS_MODULE,
	.open = keasy_open,
	.release = keasy_release,
	.unlocked_ioctl = keasy_ioctl
};

static int __init keasy_init(void) {
	dev_t dev;

	if (alloc_chrdev_region(&dev, 0, 1, DEVICE_NAME))
		return -EBUSY;

	cinfo.major = MAJOR(dev);

	cdev_init(&cinfo.cdev, &keasy_fops);
	cinfo.cdev.owner = THIS_MODULE;

	if (cdev_add(&cinfo.cdev, dev, 1))
		goto ERR_CDEV_ADD;

	cinfo.class = class_create(THIS_MODULE, CLASS_NAME);
	if (IS_ERR(cinfo.class))
		goto ERR_CLASS_CREATE;

	device_create(cinfo.class, NULL, MKDEV(cinfo.major, 0), NULL, DEVICE_NAME);
	return 0;

ERR_CLASS_CREATE:
	cdev_del(&cinfo.cdev);
ERR_CDEV_ADD:
	unregister_chrdev_region(dev, 1);
	return -EBUSY;
}

static void __exit keasy_exit(void) {
	device_destroy(cinfo.class, MKDEV(cinfo.major, 0));
	class_destroy(cinfo.class);

	cdev_del(&cinfo.cdev);
	unregister_chrdev_region(MKDEV(cinfo.major, 0), 1);
}

// 内核模块初始化
module_init(keasy_init);

// 内核模块退出
module_exit(keasy_exit);

// 内核模块作者
MODULE_AUTHOR("bros");

// 内核模块协议
MODULE_LICENSE("GPL");

// 内核模块描述
MODULE_DESCRIPTION("Easiest kernel chall of ur life");
