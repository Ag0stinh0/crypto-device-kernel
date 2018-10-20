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
   char stringToSend[BUFFER_LENGTH], operation, stringResult[BUFFER_LENGTH];
   printf("This is Crypto Kernel...\n\nc - cipher a plaintext\nd - decipher a ciphertext\nh - hash256 of a plaintext\n");
   fd = open("/dev/crypto", O_RDWR);             // Open the device with read/write access
   if (fd < 0){
      perror("Failed to open the device...");
      return errno;
   }
   printf("Type the operation with the plaintext with spaces between:\n");
   scanf("%c %[^\n]%*c", operation, stringToSend);      // Read in a string (with spaces)

   //codigo do lucas faz a transformers do stringToSend

   strcat(stringResult,operation);
   strcat(stringResult,' ');
   strcat(stringResult,stringToSend);

   ret = write(fd, stringResult, strlen(stringResult));    // Send the string to the LKM
   if (ret < 0){
      perror("Failed to write the message to the device.");
      return errno;
   }

   printf("Press ENTER to receive the ciphertext...\n");
   getchar();

   ret = read(fd, receive, BUFFER_LENGTH);        // Read the response from the LKM
   if (ret < 0){
      perror("Failed to read the message from the device.");
      return errno;
   }

   printf("Your ciphertext: %s\n", receive);
   printf("End of Crypto\n");
   return 0;
}
