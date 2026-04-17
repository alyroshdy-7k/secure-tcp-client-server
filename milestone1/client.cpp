#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <iostream>
#include <fstream>
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
    if (strstr(buf, "login") == NULL) { printf("Auth Failed\n"); return 1; }
    
    int menu_level = 0;
    if (strstr(buf, "admin")) menu_level = 3;
    else if (strstr(buf, "topeditor")) menu_level = 2;
    else if (strstr(buf, "mediumguest")) menu_level = 1;

    printf("Access Granted: %s\n", buf);

    while (1) {
        printf("\n--- COMMAND MENU ---\n");
        printf("1. ls (List Server Files)\n");
        printf("2. READ\n");
        if (menu_level >= 2) { printf("3. CREATE\n4. EDIT\n"); }
        if (menu_level == 3) { printf("5. DELETE\n6. UPLOAD\n7. DOWNLOAD\n"); }
        printf("Choose: ");
        
        int choice; scanf("%d", &choice); getchar();
        char cmd[20] = "", fname[50] = "NONE", data[512] = "";

        if (choice == 1) strcpy(cmd, "ls");
        else if (choice == 2) strcpy(cmd, "READ");
        else if (choice == 3 && menu_level >= 2) strcpy(cmd, "CREATE");
        else if (choice == 4 && menu_level >= 2) strcpy(cmd, "EDIT");
        else if (choice == 5 && menu_level == 3) strcpy(cmd, "DELETE");
        else if (choice == 6 && menu_level == 3) strcpy(cmd, "UPLOAD");
        else if (choice == 7 && menu_level == 3) strcpy(cmd, "DOWNLOAD");

        if (strlen(cmd) == 0) { printf("Invalid choice.\n"); continue; }

        if (strcmp(cmd, "ls") != 0) {
            printf("Filename: "); scanf("%s", fname); getchar();
        }
        
        if (strcmp(cmd, "CREATE") == 0 || strcmp(cmd, "EDIT") == 0 || strcmp(cmd, "UPLOAD") == 0) {
            if (strcmp(cmd, "UPLOAD") == 0) {
                std::ifstream f(fname);
                if (f.is_open()) {
                    std::string s((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
                    strcpy(data, s.c_str());
                } else { printf("Local file not found.\n"); continue; }
            } else {
                printf("Enter text: "); fgets(data, 512, stdin);
                data[strcspn(data, "\n")] = 0;
            }
        }

        sprintf(buf, "%s %s %s", cmd, fname, data);
        unsigned char encrypted[1024] = {0};
        aes_encrypt((unsigned char*)buf, 1024, encrypted);
        send(sock, encrypted, 1024, 0);

        n = read(sock, buf, 1024);
        if (n > 0) {
            unsigned char decrypted[1024] = {0};
            aes_decrypt((unsigned char*)buf, 1024, decrypted);
            
            if (strcmp(cmd, "DOWNLOAD") == 0 && strstr((char*)decrypted, "DENIED") == NULL) {
                std::ofstream f(fname); f << (char*)decrypted; f.close();
                printf("Download successful.\n");
            } else {
                printf("[SERVER RESPONSE]:\n%s\n", decrypted);
            }
        }
    }
    close(sock); return 0;
}
