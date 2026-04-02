#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "security.h"

#define PORT 8080
#define BUFFER_SIZE 1024

int authenticate(char *user, char *pass) {
    FILE *file = fopen("users.txt", "r");
    if (!file) return 0;
    char f_u[50], f_p[50], f_r[20];
    while (fscanf(file, "%s %s %s", f_u, f_p, f_r) != EOF) {
        if (strcmp(user, f_u) == 0 && strcmp(pass, f_p) == 0) {
            fclose(file);
            return 1;
        }
    }
    fclose(file);
    return 0;
}

void* Shandle_client(void* arg) {
    int client_sock = *((int*)arg);
    free(arg);
    char buffer[BUFFER_SIZE], user[50], pass[50];

    int n = read(client_sock, buffer, BUFFER_SIZE);
    if (n <= 0) { close(client_sock); return NULL; }
    buffer[n] = '\0';
    sscanf(buffer, "%s %s", user, pass);

    if (authenticate(user, pass)) {
        send(client_sock, "AUTH_OK", 7, 0);
        printf("\n[AUTH] User '%s' logged in on [Socket %d]\n", user, client_sock);
    } else {
        send(client_sock, "AUTH_FAIL", 9, 0);
        close(client_sock);
        return NULL;
    }

    while ((n = read(client_sock, buffer, BUFFER_SIZE)) > 0) {
        int aes_len = ((n + 15) / 16) * 16; 
        unsigned char decrypted[BUFFER_SIZE];
        memset(decrypted, 0, BUFFER_SIZE); // CLEAN BUFFER TO FIX DIAMOND SYMBOLS

        printf("\n[SERVER - Socket %d] RECEIVED ENCRYPTED FROM %s: ", client_sock, user);
        for(int i=0; i<n; i++) printf("%02x", (unsigned char)buffer[i]);

        aes_decrypt((unsigned char*)buffer, aes_len, decrypted);
        
        // Output decrypted message ONLY on server
        printf("\n[SERVER - Socket %d] DECRYPTED MESSAGE: %s\n", client_sock, decrypted);

        char resp_text[] = "ACK: Message Received";
        unsigned char encrypted_resp[BUFFER_SIZE] = {0};
        aes_encrypt((unsigned char*)resp_text, 32, encrypted_resp);
        send(client_sock, encrypted_resp, 32, 0);
    }

    close(client_sock);
    return NULL;
}

int main() {
    int s_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(s_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr = {AF_INET, htons(PORT), INADDR_ANY};
    bind(s_fd, (struct sockaddr*)&addr, sizeof(addr));
    listen(s_fd, 5);
    printf("--- MULTI-THREADED AES SERVER ACTIVE ---\n");
    while (1) {
        int *c_sock = (int*)malloc(sizeof(int));
        *c_sock = accept(s_fd, NULL, NULL);
        printf("[SYSTEM] New connection assigned to [Socket %d]\n", *c_sock);
        pthread_t t;
        pthread_create(&t, NULL, handle_client, c_sock);
        pthread_detach(t);
    }
    return 0;
}
