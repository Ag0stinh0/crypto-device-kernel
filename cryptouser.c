#include<stdio.h>
#include<stdlib.h>
#include<errno.h>
#include<fcntl.h>
#include<string.h>
#include<unistd.h>

#define BUFFER_LENGTH 256               ///< The buffer length (crude but fine)
static char receive[BUFFER_LENGTH];     ///< The receive buffer from the LKM

int main()
{
    int ret, fd;
    char stringToSend[BUFFER_LENGTH];

    printf("This is Crypto Kernel...\n\nc - cipher a plaintext\nd - decipher a ciphertext\nh - hash256 of a plaintext\n");
    fd = open("/dev/crypto", O_RDWR);             // Open the device with read/write access
    if (fd < 0){
        perror("Failed to open the device...");
        return errno;
    }

    printf("Type the operation with the plaintext with spaces between:\n");
    scanf("%[^\n]%*c", stringToSend);      // Read in a string (with spaces)

    ret = write(fd, stringToSend, strlen(stringToSend));    // Send the string to the LKM
    if (ret < 0){
        perror("Failed to write the message to the device.");
        return errno;
    }

    printf("Press ENTER to receive the answer...\n");
    getchar();

    ret = read(fd, receive, BUFFER_LENGTH);        // Read the response from the LKM
    if (ret < 0){
        perror("Failed to read the message from the device.");
        return errno;
    }

    if(*stringToSend == 'c'){ // ***************************************
        printf("Your ciphertext: ");
        for(int i = 0; i < strlen(receive); i++)
            printf("%x", (unsigned char) receive[i]);
        printf("\n\n");
    }
    else{
	if(*stringToSend == 'h'){
	printf("Your ciphertext: %s\n\n", receive);
	}
		else{
        	printf("Your plaintext: ");
        	for(int i = 0; i < strlen(receive); i++)
            		printf("%x", (unsigned char) receive[i]);
        	printf("\n\n");
		}
	}

    printf("End of Crypto\n");
    return 0;
}
