// SPDX-License-Identifier: GPL-2.0
#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/random.h>
#include <linux/cdev.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Engin Polat");
MODULE_DESCRIPTION("Random Strong Password Generator");

#define DEVICE_NAME "spg"
#define BUFFER_SIZE 64

static char password[BUFFER_SIZE];
static int password_len = 16;
static dev_t spg_dev_number;

static void generate_password(void)
{
  const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
  int i;

  for (i = 0; i < password_len; ++i)
  {
    password[i] = charset[get_random_int() % (sizeof(charset) - 1)];
  }
  password[password_len] = '\0';
}

static int spg_open(struct inode *inode, struct file *file)
{
  generate_password();
  return 0;
}

static ssize_t spg_read(struct file *file, char __user *buf, size_t len, loff_t *offset)
{
  int bytes_to_copy;

  if (*offset >= password_len)
    return 0;

  bytes_to_copy = min(len, (size_t)(password_len - *offset));

  if (copy_to_user(buf, password + *offset, bytes_to_copy))
    return -EFAULT;

  *offset += bytes_to_copy;

  return bytes_to_copy;
}

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = spg_open,
    .read = spg_read,
};

static struct cdev cdev;

static int __init spg_init(void)
{
  int ret;

  spg_dev_number = MKDEV(42, 0);

  cdev_init(&cdev, &fops);
  cdev.owner = THIS_MODULE;
  ret = cdev_add(&cdev, spg_dev_number, 1);
  if (ret < 0)
  {
    printk(KERN_ALERT "Failed to register a device.\n");
    return ret;
  }

  printk(KERN_INFO "Registered device: /dev/%s, Major number: %d\n", DEVICE_NAME, MAJOR(spg_dev_number));

  return 0;
}

static void __exit spg_exit(void)
{
  cdev_del(&cdev);

  unregister_chrdev_region(spg_dev_number, 1);
  printk(KERN_INFO "Unregistered device: /dev/%s\n", DEVICE_NAME);
}

module_init(spg_init);
module_exit(spg_exit);
