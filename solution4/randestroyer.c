#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ThatFatPat and nmraz");

#define MY_MAJOR 69
#define MY_MAX_MINORS 1

struct my_device_data {
  struct cdev cdev;
  /* my data starts here */
  //...
};

struct my_device_data devs[MY_MAX_MINORS];

const struct file_operations my_fops = {.owner = THIS_MODULE,
                                        .open = my_open,
                                        .read = my_read,
                                        .write = my_write,
                                        .release = my_release,
                                        .unlocked_ioctl = my_ioctl};

int init_module(void) {
  int i, err;

  err = register_chrdev_region(MKDEV(MY_MAJOR, 0), 1, "randestroyer");
  if (err != 0) {
    /* report error */
    return err;
  }

  for (i = 0; i < MY_MAX_MINORS; i++) {
    /* initialize devs[i] fields */
    cdev_init(&devs[i].cdev, &my_fops);
    cdev_add(&devs[i].cdev, MKDEV(MY_MAJOR, i), 1);
  }

  return 0;
});
module_exit(lkm_example_exit);