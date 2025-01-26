#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input)
{
    char buffer[10];
    strcpy(buffer, input); // Potential buffer overflow vulnerability
    printf("Buffer: %s\n", buffer);
}

int main()
{
    char input[20] = "This is too long";
    vulnerable_function(input);
    return 0;
}
