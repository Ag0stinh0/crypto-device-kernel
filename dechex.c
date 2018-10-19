#include <stdio.h>
#include <stdlib.h>
#include <string.h>



int pegaDecimal(char c)
{
    int d;
    d = c;
    return d;
}

void pegaHexa(int d, char hexa[])
{
    //char hexa[2];
    int  quo, resto;

    do{
        quo = d / 16;
            resto = d % 16;
            d /= 16;
            
            switch(resto){
                case 10:
                    strcat(hexa, "A");
                break;
                case 11:
                    strcat(hexa, "B");
                break;
                case 12:
                    strcat(hexa, "C");
                break;
                case 13:
                    strcat(hexa, "D");
                break;
                case 14:
                    strcat(hexa, "E");
                break;
                case 15:
                    strcat(hexa, "F");
                break;
                case 16:
                    strcat(hexa, "G");
                break;
                default:
                    sprintf(getInt, "%i", resto);
                    strcat(hexa, getInt);
            }
        }while(q != 0);
}

void main()
{

    //do

}