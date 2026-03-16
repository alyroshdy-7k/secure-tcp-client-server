#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "security.h"

#define PORT 8080
#define BUFFER_SIZE 1024

int main()
{
    int sock;
    struct sockaddr_in server_address;

    char buffer[BUFFER_SIZE] = {0};
    char auth_key[] = "secure123";
    char xor_key[] = "key123";

    char message[] = "Hello from client";
    int message_len = strlen(message);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        printf("Socket creation failed\n");
        return 1;
    }

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT);
    server_address.sin_addr.s_addr = INADDR_ANY;

    if (connect(sock, (struct sockaddr*)&server_address, sizeof(server_address)) < 0)
    {
        printf("Connection failed\n");
        close(sock);
        return 1;
    }

    send(sock, auth_key, strlen(auth_key) + 1, 0);

    int auth_bytes = read(sock, buffer, BUFFER_SIZE - 1);
    if (auth_bytes <= 0)
    {
        printf("Failed to receive authentication response\n");
        close(sock);
        return 1;
    }

    buffer[auth_bytes] = '\0';

    if (strcmp(buffer, "AUTH_OK") != 0)
    {
        printf("Authentication failed\n");
        close(sock);
        return 0;
    }

    printf("Authentication successful!\n");
    printf("Original message: %s\n", message);

    xor_encrypt_decrypt(message, message_len, xor_key);
    printf("Encrypted message sent\n");
    send(sock, message, message_len, 0);

    int n = read(sock, buffer, BUFFER_SIZE);
    if (n <= 0)
    {
        printf("Failed to receive encrypted reply\n");
        close(sock);
        return 1;
    }

    printf("Encrypted reply received\n");

    xor_encrypt_decrypt(buffer, n, xor_key);
    buffer[n] = '\0';

    printf("Decrypted reply: %s\n", buffer);

    close(sock);
    return 0;
}
