#include <linux/init.h> // Macros used to mark up functions e.g. __init __exit
#include <linux/module.h> // Core header for loading LKMs into the kernel
#include <linux/device.h> // Header to support the kernel Driver Model
#include <linux/crypto.h>
#include <linux/kernel.h>  // Contains types, macros, functions for the kernel
#include <linux/fs.h>      // Header for the Linux file system support
#include <linux/uaccess.h> // Required for the copy to user function
#include <linux/scatterlist.h>
#include <crypto/internal/hash.h>
#include <crypto/internal/skcipher.h>

#define DEVICE_NAME "crypto" ///< The device will appear at /dev/ebbchar using this value
#define CLASS_NAME  "cpt"     ///< The device class -- this is a character device driver

#define HASH_LENGTH (256/8) ///< length of hash256
#define SYMMETRIC_KEY_LENGTH 32
#define CIPHER_BLOCK_SIZE 16

MODULE_LICENSE("GPL");                                                ///< The license type -- this affects available functionality
MODULE_AUTHOR("Evandro Agostinho Pedro Lucas Brunno");                ///< The author -- visible when you use modinfo
MODULE_DESCRIPTION("Modulo de Linux para criptografar uma mensagem"); ///< The description -- see modinfo
MODULE_VERSION("0.1");

static char *key;

static int majorNumber;                             ///< Stores the device number -- determined automatically
static short size_of_message;                       ///< Used to remember the size of the string stored
static int numberOpens = 0;                         ///< Counts the number of times the device is opened
static struct class *cryptoClass = NULL;            ///< The device-driver class struct pointer
static struct device *cryptoDevice = NULL;          ///< The device-driver device struct pointer

char *final;

// Parameters
module_param(key, charp, 0000);
MODULE_PARM_DESC(key, "Chave para criptografia");

// The prototype functions for the character driver
static int dev_open(struct inode *, struct file *);
static int dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);

// File Struct
static struct file_operations fops =
{
    .open = dev_open,
    .read = dev_read,
    .write = dev_write,
    .release = dev_release,
};

// AES Struct
struct tcrypt_result {
    struct completion completion;
    int err;
};

// Tie all data structures together
struct skcipher_def {
    struct scatterlist sg;
    struct crypto_skcipher *tfm;
    struct skcipher_request *req;
    struct tcrypt_result result;
};

// Callback function
static void test_skcipher_cb(struct crypto_async_request *req, int error)
{
    struct tcrypt_result *result = req->data;
    int i = 13;

    if (error == -EINPROGRESS)
        return;
    result->err = error;
    complete(&result->completion);
    pr_info("Encryption finished successfully %i\n", 13);
}

// Perform cipher operation
/*
static unsigned int test_skcipher_encdec(struct skcipher_def *sk, int enc)
{
    int rc = 0;

    if (enc)
        rc = crypto_skcipher_encrypt(sk->req);
    else
        rc = crypto_skcipher_decrypt(sk->req);

    switch (rc) {
    case 0:
        break;
    case -EINPROGRESS:
    case -EBUSY:
        rc = wait_for_completion_interruptible(
            &sk->result.completion);
        if (!rc && !sk->result.err) {
            reinit_completion(&sk->result.completion);
            break;
        }
    default:
        pr_info("skcipher encrypt returned with %d result %d\n",rc, sk->result.err);
        break;
    }
    init_completion(&sk->result.completion);

    return rc;
}*/

/* Initialize and trigger cipher operation */
static int encrypt_create(char *msg, int sel)
{
    struct skcipher_def sk;
    struct crypto_skcipher *skcipher = NULL;
    struct skcipher_request *req = NULL;
    char str[256];

    char *ivdata = NULL;

    int ret = -EFAULT;
    int i;

    struct crypto_cipher *cipher = NULL; 

    cipher = crypto_alloc_cipher("ecb-aes-aesni", 0, 0); //cbc
    if (IS_ERR(cipher)) {
        pr_info("could not allocate skcipher handle\n");
        return PTR_ERR(cipher);
    }
/*
    req = cipher_request_alloc(cipher, GFP_KERNEL);
    if (!req) {
        pr_info("could not allocate skcipher request\n");
        ret = -ENOMEM;
        goto out;
    }

    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,test_skcipher_cb,&sk.result);
*/
    /* AES 256 with random key */
    if (crypto_cipher_setkey(cipher, key, SYMMETRIC_KEY_LENGTH)) {
        pr_info("key could not be set\n");
        ret = -EAGAIN;
        goto out;
    }

    /* IV will be random */
    ivdata = kmalloc(CIPHER_BLOCK_SIZE, GFP_KERNEL);
    if (!ivdata) {
        pr_info("could not allocate ivdata\n");
        goto out;
    }
    get_random_bytes(ivdata, CIPHER_BLOCK_SIZE);

    
    sk.req = req;

    /* We encrypt one block */
    sg_init_one(&sk.sg, msg, CIPHER_BLOCK_SIZE);
    skcipher_request_set_crypt(req, &sk.sg, &sk.sg, CIPHER_BLOCK_SIZE, ivdata);
    init_completion(&sk.result.completion);

    /* encrypt data */
    /*ret = test_skcipher_encdec(&sk, sel);
    
    if (ret)
        goto out;*/

    if(sel)
    crypto_cipher_encrypt_one(cipher, msg, msg);
    else
    crypto_cipher_decrypt_one(cipher, msg, msg);

    //strcpy(msg,sk.result.completion);
    //for(i = 0; i < strlen(msg); i++)
       // sprintf(msg, "%s", (unsigned char)sk.result.completion);

    //pr_info("This is the encrypted message: %x\n", sk.result.completion);

    out:
    if (skcipher)
        crypto_free_skcipher(skcipher);
    if (req)
        skcipher_request_free(req);
    if (ivdata)
        kfree(ivdata);

    return ret;
}

// Hash Functions
static void show_hash(char *hash_text, char *msg){
    int i;
    char str[HASH_LENGTH * 2 + 1];

    for(i = 0; i < HASH_LENGTH; i++)
        sprintf(&str[i*2], "%02x", (unsigned char)hash_text[i]);
    str[i*2] = 0;
    strcpy(msg,str);

    pr_info("This is the hash message: %s\n", str);
}

void hash_create(char *msg){
    char hash_sha256[HASH_LENGTH];
    struct crypto_shash *sha256;
    struct shash_desc *shash;

    pr_info("This is the pre-hash message: %s\n", msg);

    sha256 = crypto_alloc_shash("sha256", 0, 0);

    if( IS_ERR(sha256) ) return -1;

    shash = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(sha256), GFP_KERNEL);

    if( !shash ) return -ENOMEM;

    shash->tfm = sha256;
    shash->flags = 0;

    if( crypto_shash_init(shash) ) return -1;
    if( crypto_shash_update(shash, msg, strlen(msg)) ) return -1;
    if( crypto_shash_final(shash, hash_sha256) ) return -1;

    kfree(shash);
    crypto_free_shash(sha256);

    show_hash(hash_sha256,msg);
}

// Module init
static int __init crypto_init(void)
{
    majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
    if (majorNumber < 0) {
        pr_alert("Registering char device failed with %d\n", majorNumber); // Criação do major number para o DEVICE FILES
        return majorNumber;
    }

    cryptoClass = class_create(THIS_MODULE, DEVICE_NAME); // Class creation
    if (IS_ERR(cryptoClass)){                // Check for error and clean up if there is
        unregister_chrdev(majorNumber, DEVICE_NAME);
        printk(KERN_ALERT "Failed to register device class\n");
        return PTR_ERR(cryptoClass);          // Correct way to return an error on a pointer
    }

    cryptoDevice = device_create(cryptoClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME); // Device Driver creation
    if (IS_ERR(cryptoDevice)){               // Clean up if there is an error
        class_destroy(cryptoClass);           // Repeated code but the alternative is goto statements
        unregister_chrdev(majorNumber, DEVICE_NAME);
        printk(KERN_ALERT "Failed to create the device\n");
        return PTR_ERR(cryptoDevice);
    }

    printk(KERN_INFO "CryptoModule: modulo crypto inicializado com a chave: %s.\n", key);
    return 0;
}

static void __exit crypto_exit(void)
{
    device_destroy(cryptoClass, MKDEV(majorNumber, 0)); // remove the device
    class_unregister(cryptoClass);                      // unregister the device class
    class_destroy(cryptoClass);                         // remove the device class
    unregister_chrdev(majorNumber, DEVICE_NAME);         // unregister the major number
    printk(KERN_INFO "CryptoModule: modulo crypto encerrado com sucesso!\n");
}

static int dev_open(struct inode *inodep, struct file *filep){
   numberOpens++;
   printk(KERN_INFO "CryptoModule: Device has been opened %d time(s)\n", numberOpens);
   return 0;
}

static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset){
    int error_count = 0;
    // copy_to_user has the format ( * to, *from, size) and returns 0 on success
    error_count = copy_to_user(buffer, final, size_of_message);

    if (error_count==0){            // if true then have success
       printk(KERN_INFO "CryptoModule: Enviou %d caracteres para o usuario\n", size_of_message);
       return (size_of_message=0);  // clear the position to the start and return 0
    }
    else {
        printk(KERN_INFO "CryptoModule: Falhou em mandar %d caracteres para o usuario\n", error_count);
        return -EFAULT;              // Failed -- return a bad address message (i.e. -14)
    }
}

static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset){
    char opc = *buffer;
    char *message = kmalloc(strlen(buffer), GFP_ATOMIC);
    int select;

    switch (opc){
        case 'd':
            strcpy(message,buffer);
            strsep(&message, " ");
            select = 0;
            encrypt_create(message, select);

            final = kmalloc(64, GFP_ATOMIC);
            strcpy(final, message);
            break;
        case 'c':
            strcpy(message,buffer);
            strsep(&message, " ");
            select = 1;
            encrypt_create(message, select);

            final = kmalloc(64, GFP_ATOMIC);
            strcpy(final, message);
            break;
        case 'h':
            strcpy(message,buffer);
            strsep(&message, " ");

            hash_create(message);

            final = kmalloc(64, GFP_ATOMIC);
            strcpy(final, message);
            break;
    }

    size_of_message = strlen(message);  // store the length of the stored message
    return len;
}

static int dev_release(struct inode *inodep, struct file *filep){
   printk(KERN_INFO "CryptoModule: O Device fechou com sucesso\n");
   return 0;
}

module_init(crypto_init);
module_exit(crypto_exit);
