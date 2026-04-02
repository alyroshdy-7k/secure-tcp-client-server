#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "security.h"

int main() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {AF_INET, htons(8080), inet_addr("127.0.0.1")};
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) return 1;

    char u[50], p[50], buf[1024];
    printf("Username: "); scanf("%s", u);
    printf("Password: "); scanf("%s", p);
    getchar();

    sprintf(buf, "%s %s", u, p);
    send(sock, buf, strlen(buf), 0);

    int n = read(sock, buf, 1024);
    buf[n] = '\0';
    if (strcmp(buf, "AUTH_OK") != 0) return 1;
    printf("Access Granted.\n");

    while (1) {
        printf("\nEnter Message: ");
        if (fgets(buf, 1024, stdin) == NULL) break;
        buf[strcspn(buf, "\n")] = 0;

        int len = strlen(buf);
        int aes_len = ((len + 15) / 16) * 16;
        unsigned char encrypted[1024] = {0};

        aes_encrypt((unsigned char*)buf, aes_len, encrypted);
        printf("[CLIENT] SENDING AES ENCRYPTED (HEX): ");
        for(int i=0; i<aes_len; i++) printf("%02x ", encrypted[i]);
        printf("\n");
        send(sock, encrypted, aes_len, 0);

        n = read(sock, buf, 1024);
        if (n > 0) {
            printf("[CLIENT] RECEIVED ENCRYPTED ACK (HEX): ");
            for(int i=0; i<n; i++) printf("%02x ", (unsigned char)buf[i]);
            printf("\n");
            // NO DECRYPTION PRINTED HERE PER REQUEST
        }
    }
    close(sock);
    return 0;
}
