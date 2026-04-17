#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <iostream>
#include <fstream>
#include <dirent.h> 
#include "security.h"

#define BUFFER_SIZE 1024

int authenticate(char *user, char *pass, char *role_out) {
    FILE *file = fopen("users.txt", "r");
    if (!file) return 0;
    char f_u[50], f_p[50], f_r[50];
    while (fscanf(file, "%s %s %s", f_u, f_p, f_r) != EOF) {
        if (strcmp(user, f_u) == 0 && strcmp(pass, f_p) == 0) {
            strcpy(role_out, f_r);
            fclose(file);
            if (strcmp(f_r, "admin") == 0) return 3;
            if (strcmp(f_r, "topeditor") == 0) return 2;
            if (strcmp(f_r, "mediumguest") == 0) return 1;
        }
    }
    fclose(file);
    return 0;
}

void* handle_client(void* arg) {
    int client_sock = *((int*)arg);
    free(arg);
    char buffer[BUFFER_SIZE], user[50], pass[50], role[50];
    int user_level = 0;

    int n = read(client_sock, buffer, BUFFER_SIZE);
    if (n <= 0) { close(client_sock); return NULL; }
    buffer[n] = '\0';
    sscanf(buffer, "%s %s", user, pass);

    user_level = authenticate(user, pass, role);
    if (user_level > 0) {
        char auth_msg[100];
        sprintf(auth_msg, "%s login", role);
        send(client_sock, auth_msg, strlen(auth_msg), 0);
        printf("[AUTH] %s (Level %d) joined on Socket %d\n", user, user_level, client_sock);
    } else {
        send(client_sock, "AUTH_FAIL", 9, 0);
        close(client_sock); return NULL;
    }

    while ((n = read(client_sock, buffer, BUFFER_SIZE)) > 0) {
        unsigned char decrypted[BUFFER_SIZE] = {0};
        aes_decrypt((unsigned char*)buffer, BUFFER_SIZE, decrypted);
        char cmd[20], fname[50], extra[BUFFER_SIZE] = {0};
        sscanf((char*)decrypted, "%s %s %[^\n]", cmd, fname, extra);
        
        char resp[BUFFER_SIZE] = "";

        // --- NEW: LS COMMAND (Available to everyone) ---
        if (strcmp(cmd, "ls") == 0) {
            printf("[COMMAND] %s requested file list (ls)\n", user);
            DIR *d; struct dirent *dir;
            d = opendir(".");
            if (d) {
                while ((dir = readdir(d)) != NULL) {
                    if (dir->d_type == DT_REG) { // Only regular files
                        strcat(resp, dir->d_name);
                        strcat(resp, "\n");
                    }
                }
                closedir(d);
            }
        }
        // Fixed to display content
        else if (strcmp(cmd, "READ") == 0) {
            printf("[COMMAND] %s requested READ on %s\n", user, fname);
            std::ifstream f(fname);
            if (f.is_open()) {
                std::string s((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
                strncpy(resp, s.c_str(), BUFFER_SIZE - 1);
                f.close();
            } else strcpy(resp, "ERROR: File Not Found");
        }
        // OTHER COMMANDS (Admin/Editor Only)
        else if (strcmp(cmd, "UPLOAD") == 0 || strcmp(cmd, "DOWNLOAD") == 0 || strcmp(cmd, "DELETE") == 0) {
            if (user_level != 3) strcpy(resp, "DENIED: Admin Only");
            else {
                if (strcmp(cmd, "DELETE") == 0) remove(fname);
                else if (strcmp(cmd, "UPLOAD") == 0) { std::ofstream f(fname); f << extra; f.close(); }
                else { // DOWNLOAD
                    std::ifstream f(fname);
                    if (f.is_open()) {
                        std::string s((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
                        strncpy(resp, s.c_str(), BUFFER_SIZE - 1);
                        f.close();
                    } else strcpy(resp, "ERROR: File Not Found");
                }
                strcpy(resp, "SUCCESS");
            }
        }
        else if (strcmp(cmd, "CREATE") == 0 || strcmp(cmd, "EDIT") == 0) {
            if (user_level < 2) strcpy(resp, "DENIED: Editor/Admin Only");
            else { std::ofstream f(fname); f << extra; f.close(); strcpy(resp, "SUCCESS"); }
        }

        unsigned char enc_resp[BUFFER_SIZE] = {0};
        aes_encrypt((unsigned char*)resp, BUFFER_SIZE, enc_resp);
        send(client_sock, enc_resp, BUFFER_SIZE, 0);
    }
    close(client_sock); return NULL;
}

int main() {
    int s_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {AF_INET, htons(8080), INADDR_ANY};
    bind(s_fd, (struct sockaddr*)&addr, sizeof(addr));
    listen(s_fd, 5);
    printf("Server Listening with LS and READ support...\n");
    while (1) {
        int *c_sock = (int*)malloc(sizeof(int));
        *c_sock = accept(s_fd, NULL, NULL);
        pthread_t t;
        pthread_create(&t, NULL, handle_client, c_sock);
        pthread_detach(t);
    }
    return 0;
}
