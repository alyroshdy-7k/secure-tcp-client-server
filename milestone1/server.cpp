#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "security.h"

#define PORT 8080
#define BUFFER_SIZE 1024

int main()
{
    int server_fd, new_socket;
    struct sockaddr_in address;
    socklen_t addrlen = sizeof(address);

    char buffer[BUFFER_SIZE] = {0};
    char received_key[BUFFER_SIZE] = {0};

    char expected_key[] = "secure123";
    char xor_key[] = "key123";

    char reply[] = "Hello from server";
    int reply_len = strlen(reply);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0)
    {
        printf("Socket creation failed\n");
        return 1;
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0)
    {
        printf("Bind failed\n");
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 3) < 0)
    {
        printf("Listen failed\n");
        close(server_fd);
        return 1;
    }

    printf("Server waiting for client...\n");

    new_socket = accept(server_fd, (struct sockaddr*)&address, &addrlen);
    if (new_socket < 0)
    {
        printf("Accept failed\n");
        close(server_fd);
        return 1;
    }

    printf("Client connected!\n");

    int key_bytes = read(new_socket, received_key, BUFFER_SIZE - 1);
    if (key_bytes <= 0)
    {
        printf("Failed to read authentication key\n");
        close(new_socket);
        close(server_fd);
        return 1;
    }

    received_key[key_bytes] = '\0';

    if (strcmp(received_key, expected_key) != 0)
    {
        printf("Authentication failed\n");
        close(new_socket);
        close(server_fd);
        return 0;
    }

    printf("Authentication successful!\n");
    send(new_socket, "AUTH_OK", 8, 0);

    int n = read(new_socket, buffer, BUFFER_SIZE);
    if (n <= 0)
    {
        printf("Failed to read encrypted message\n");
        close(new_socket);
        close(server_fd);
        return 1;
    }

    printf("Encrypted message received\n");

    xor_encrypt_decrypt(buffer, n, xor_key);
    buffer[n] = '\0';

    printf("Decrypted message: %s\n", buffer);

    xor_encrypt_decrypt(reply, reply_len, xor_key);
    send(new_socket, reply, reply_len, 0);

    close(new_socket);
    close(server_fd);
    return 0;
}
