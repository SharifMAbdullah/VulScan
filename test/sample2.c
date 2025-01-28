#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void vulnerable_strcpy(const char *input)
{
    char buffer[50];
    strcpy(buffer, input); // Vulnerability: No bounds checking
    printf("Copied string: %s\n", buffer);
}

int vulnerable_integer_overflow(int a, int b)
{
    return a + b;
}

void vulnerable_memory_leak()
{
    char *leak = malloc(100);
    strcpy(leak, "This is a memory leak");
    printf("%s\n", leak);
}