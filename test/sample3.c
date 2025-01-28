#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_USERS 100

struct User
{
    char username[20];
    char password[20];
};

struct User users[MAX_USERS];

void add_user(const char *username, const char *password)
{
    strcpy(users[MAX_USERS].username, username);
    strcpy(users[MAX_USERS].password, password);
}

void vulnerable_format_string(const char *user_input)
{
    printf(user_input);
}