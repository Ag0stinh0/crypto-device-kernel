// hash.c a hash256 Kernel Module

#include<linux/module.h>
#include<linux/kernel.h>
#include<linux/init.h>
#include<crypto/internal/hash.h>
#include<linux/moduleparam.h>

#define HASH_LENGTH (256/8) //Size of hash256

static plaintext[HASH_LENGTH * 2 + 1]; //String received in command line // O TEXTO PRECISA SER PEGO NO ARQUIVO
module_param(plaintext, charp, 0); // RETIRAR ESSA LINHA

static void show_hash(char *hash_text){
    int i;
    char str[HASH_LENGTH * 2 + 1];

    for(i = 0; i < HASH_LENGTH; i++)
        sprintf(&str[i*2], "%02x", (unsigned char)hash_text[i]);
    str[i*2] = 0;
    pr_info("%s\n", str);
}

int hash_init(void){
    char hash_sha256[HASH_LENGTH];
    struct crypto_shash *sha256;
    struct shash_desc *shash;

    sha256 = crypto_alloc_shash("sha256", 0, 0);

    if( IS_ERR(sha256) ) return -1

    shash = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(sha256), GFP_KERNEL);

    if( !shash ) return -ENOMEM;

    shash->tfm = sha256;
    shash->flags = 0;

    if( crypto_shash_init(shash) ) return -1;
    if( crypto_shash_update(shash, plaintext, strlen(plaintext)) ) return -1;
    if( crypto_shash_final(shash, hash_sha256) ) return -1;

    kfree(shash);
    crypto_free_shash(sha256);

    show_hash(hash_sha256);

    return 0;
}

void hash_exit(void){}

module_init(hash_init);
module_exit(hash_exit);
MODULE_LICENSE("GPL");
