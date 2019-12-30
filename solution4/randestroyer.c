#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/uaccess.h>

#define MY_MAJOR 1

struct my_device_data {
  struct cdev cdev;
  /* my data starts here */
  //...
};

struct my_device_data dev;

static int my_open(struct inode *inode, struct file *file){
//   struct my_device_data *my_data;
//   my_data = container_of(inode->i_cdev, struct my_device_data, cdev);
//   file->private_data = my_data;
  return 0;
}
static long int my_read(struct file *file, char __user *user_buffer, size_t size, loff_t *offset){
  // struct my_device_data *my_data;
  // my_data = (struct my_device_data*) file->private_data;
	printk(KERN_WARNING "Entered my_read");
	char A = 'A';
	for (size_t i = 0; i < size; i++)
	{
		copy_to_user(user_buffer + i, &A, 1);
	}
	return size;
}

const struct file_operations my_fops = {.owner = THIS_MODULE,
                                        .open = my_open,
                                        .read = my_read,
                                        // .write = my_write,
                                        // .release = my_release,
                                        // .unlocked_ioctl = my_ioctl
};

int __init init_randestroyer_module(void) {
	unregister_chrdev_region(MKDEV(1, 8), 1);

	int err = register_chrdev_region(MKDEV(1, 8), 1, "randestroyer");
	if (err != 0) {
		printk(KERN_WARNING "Failed to register selected chrdev region");
		return err;
	}

	cdev_init(&dev.cdev, &my_fops);
	cdev_add(&dev.cdev, MKDEV(1, 8), 1);
  return 0;
}

void __exit exit_randestroyer_module(void){
  cdev_del(&dev.cdev);
  unregister_chrdev_region(MKDEV(1, 8), 1);
}

module_init(init_randestroyer_module);
module_exit(exit_randestroyer_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ThatFatPat and nmraz");