#ifndef _KEASY_H
#define _KEASY_H

#define DEVICE_NAME "keasy"
#define CLASS_NAME  DEVICE_NAME

struct chrdev_info {
	unsigned int major;
	struct cdev cdev;
	struct class *class;
};

#endif
