#include <linux/init.h> // Macros used to mark up functions e.g. __init __exit
#include <linux/module.h> // Core header for loading LKMs into the kernel   
#include <linux/device.h> // Header to support the kernel Driver Model
#include <linux/crypto.h>
#include <linux/kernel.h>  // Contains types, macros, functions for the kernel
#include <linux/fs.h>      // Header for the Linux file system support
#include <linux/uaccess.h> // Required for the copy to user function
#include <linux/scatterlist.h>

#define DEVICE_NAME "crypto" ///< The device will appear at /dev/ebbchar using this value
#define CLASS_NAME "cpt"     ///< The device class -- this is a character device driver

MODULE_LICENSE("GPL");                                                ///< The license type -- this affects available functionality
MODULE_AUTHOR("Evandro Agostinho Pedro Lucas Brunno");                                  ///< The author -- visible when you use modinfo
MODULE_DESCRIPTION("Modulo de Linux para cryptografar uma mensagem"); ///< The description -- see modinfo
MODULE_VERSION("0.1");   

static char *key = "0123456789ABCDEF";

static int majorNumber;                     ///< Stores the device number -- determined automatically
static char message[256] = {0};             ///< Memory for the string that is passed from userspace
static short size_of_message;               ///< Used to remember the size of the string stored
static int numberOpens = 0;                 ///< Counts the number of times the device is opened
static struct class *cryptoClass = NULL;   ///< The device-driver class struct pointer
static struct device *cryptoDevice = NULL; ///< The device-driver device struct pointer

//receber por parametros

module_param(key, charp, 0000);
MODULE_PARM_DESC(key, "Chave para cryptografia");

// The prototype functions for the character driver -- must come before the struct definition
static int dev_open(struct inode *, struct file *);
static int dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);
static void my_test(void);

/** @brief Devices are represented as file structure in the kernel. The file_operations structure from
 *  /linux/fs.h lists the callback functions that you wish to associated with your file operations
 *  using a C99 syntax structure. char devices usually implement open, read, write and release calls
 */
static struct file_operations fops =
    {
        .open = dev_open,
        .read = dev_read,
        .write = dev_write,
        .release = dev_release,
};

/** @brief The LKM initialization function
 *  The static keyword restricts the visibility of the function to within this C file. The __init
 *  macro means that for a built-in driver (not a LKM) the function is only used at initialization
 *  time and that it can be discarded and its memory freed up after that point.
 *  @return returns 0 if successful
 */

static int __init crypto_init(void)
{
    printk(KERN_INFO "CryptoModule: modulo crypto inicializado com a chave: %s.\n", key);
}

static void __exit crypto_exit(void)
{
    //device_destroy(cryptoClass, MKDEV(majorNumber, 0)); // remove the device
    //class_unregister(cryptoClass);                      // unregister the device class
    //class_destroy(cryptoClass);                         // remove the device class
    //unregister_chrdev(majorNumber, DEVICE_NAME);         // unregister the major number
    printk(KERN_INFO "CryptoModule: modulo crypto encerrado com sucesso!\n");
}

module_init(crypto_init);
module_exit(crypto_exit);