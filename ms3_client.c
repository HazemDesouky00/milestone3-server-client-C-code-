#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/aes.h>

#define PORT 8080
#define BUFFER_SIZE 4096
#define AES_KEY_SIZE 16

unsigned char AES_KEY_DATA[AES_KEY_SIZE] = "thisisasecretkey";

int send_all(int sock, const void *buf, int len) {
    int total = 0;
    const char *ptr = (const char *)buf;
    while (total < len) {
        int s = send(sock, ptr + total, len - total, 0);
        if (s <= 0) return -1;
        total += s;
    }
    return total;
}

int recv_all(int sock, void *buf, int len) {
    int total = 0;
    char *ptr = (char *)buf;
    while (total < len) {
        int r = recv(sock, ptr + total, len - total, 0);
        if (r <= 0) return -1;
        total += r;
    }
    return total;
}

int send_string(int sock, const char *str) {
    int len = strlen(str);
    int net_len = htonl(len);
    if (send_all(sock, &net_len, sizeof(net_len)) < 0) return -1;
    if (send_all(sock, str, len) < 0) return -1;
    return 0;
}

int recv_string(int sock, char *buf, int max) {
    int net_len;
    if (recv_all(sock, &net_len, sizeof(net_len)) < 0) return -1;
    int len = ntohl(net_len);
    if (len <= 0 || len >= max) return -1;
    if (recv_all(sock, buf, len) < 0) return -1;
    buf[len] = '\0';
    return len;
}

int send_encrypted(int sock, const unsigned char *plain) {
    AES_KEY enc_key;
    unsigned char padded[BUFFER_SIZE], cipher[BUFFER_SIZE];
    int plen = strlen((const char *)plain);
    if (plen <= 0 || plen >= BUFFER_SIZE) return -1;

    int padded_len = ((plen / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
    memset(padded, 0, sizeof(padded));
    memcpy(padded, plain, plen);

    unsigned char pad = padded_len - plen;
    for (int i = plen; i < padded_len; i++) padded[i] = pad;

    AES_set_encrypt_key(AES_KEY_DATA, 128, &enc_key);
    for (int i = 0; i < padded_len; i += AES_BLOCK_SIZE)
        AES_ecb_encrypt(padded + i, cipher + i, &enc_key, AES_ENCRYPT);

    int net_len = htonl(padded_len);
    if (send_all(sock, &net_len, sizeof(net_len)) < 0) return -1;
    if (send_all(sock, cipher, padded_len) < 0) return -1;

    return 0;
}

int recv_encrypted(int sock, unsigned char *plain, int max) {
    AES_KEY dec_key;
    unsigned char cipher[BUFFER_SIZE], decr[BUFFER_SIZE];
    int net_len;

    if (recv_all(sock, &net_len, sizeof(net_len)) < 0) return -1;

    int clen = ntohl(net_len);
    if (clen <= 0 || clen > BUFFER_SIZE || clen % AES_BLOCK_SIZE != 0) return -1;

    if (recv_all(sock, cipher, clen) < 0) return -1;

    AES_set_decrypt_key(AES_KEY_DATA, 128, &dec_key);
    for (int i = 0; i < clen; i += AES_BLOCK_SIZE)
        AES_ecb_encrypt(cipher + i, decr + i, &dec_key, AES_DECRYPT);

    unsigned char pad = decr[clen - 1];
    if (pad <= 0 || pad > AES_BLOCK_SIZE) return -1;

    int plen = clen - pad;
    if (plen < 0 || plen >= max) return -1;

    memcpy(plain, decr, plen);
    plain[plen] = '\0';
    return plen;
}

int role_to_level(const char *role) {
    if (strcasecmp(role, "top") == 0) return 3;
    if (strcasecmp(role, "medium") == 0) return 2;
    return 1;
}

const char *level_label(int level) {
    if (level == 3) return "Top Level";
    if (level == 2) return "Medium Level";
    return "Entry Level";
}

void print_menu(int level) {
    printf("\n====================================================\n");
    printf("Access Level: %s\n", level_label(level));
    printf("====================================================\n");
    printf("whoami                - Show your role\n");
    printf("ls                    - List files\n");
    printf("cat <file>            - Print file contents\n");
    printf("chat                  - Enter free chat mode\n");

    if (level >= 2) {
        printf("read <file>           - Read file\n");
        printf("copy <src> <dst>      - Copy file\n");
        printf("edit <file> <text>    - Overwrite file\n");
    }

    if (level >= 3) {
        printf("upload <file>         - Upload file to server\n");
        printf("download <file>       - Download file from server\n");
        printf("delete <file>         - Delete file on server\n");
    }

    printf("exit                  - Disconnect\n");
    printf("====================================================\n");
}

int main() {
    int sock;
    struct sockaddr_in srv;
    char username[128], password[128], credentials[256];
    char auth_response[64];
    char input[BUFFER_SIZE];
    unsigned char reply[BUFFER_SIZE];
    int access_level = 1;

    printf("Enter username: ");
    scanf("%127s", username);

    printf("Enter password: ");
    scanf("%127s", password);

    snprintf(credentials, sizeof(credentials), "%s:%s", username, password);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    srv.sin_family = AF_INET;
    srv.sin_port = htons(PORT);

    if (inet_pton(AF_INET, "127.0.0.1", &srv.sin_addr) <= 0) {
        perror("inet_pton");
        close(sock);
        exit(EXIT_FAILURE);
    }

    if (connect(sock, (struct sockaddr *)&srv, sizeof(srv)) < 0) {
        perror("connect");
        close(sock);
        exit(EXIT_FAILURE);
    }

    if (send_string(sock, credentials) < 0) {
        perror("send credentials");
        close(sock);
        exit(EXIT_FAILURE);
    }

    if (recv_string(sock, auth_response, sizeof(auth_response)) < 0) {
        perror("recv auth");
        close(sock);
        exit(EXIT_FAILURE);
    }

    if (strncmp(auth_response, "AUTH_FAIL", 9) == 0) {
        printf("Authentication failed! Wrong username or password.\n");
        close(sock);
        return 1;
    }

    char *pipe_pos = strchr(auth_response, '|');
    if (pipe_pos) {
        access_level = role_to_level(pipe_pos + 1);
    }

    printf("\nAuthenticated successfully!\n");
    print_menu(access_level);

    getchar();

    while (1) {
        printf("\n[%s] $ ", level_label(access_level));

        if (fgets(input, sizeof(input), stdin) == NULL) break;
        input[strcspn(input, "\n")] = '\0';

        if (strlen(input) == 0) continue;

        char fname[256];

        if (strcmp(input, "chat") == 0) {
            if (send_encrypted(sock, (unsigned char *)"chat") < 0) break;
            if (recv_encrypted(sock, reply, sizeof(reply)) < 0) break;

            printf("Server: %s\n", reply);
            printf("You are now in chat mode. Type 'endchat' to go back.\n");

            while (1) {
                printf("[chat] $ ");

                if (fgets(input, sizeof(input), stdin) == NULL) break;
                input[strcspn(input, "\n")] = '\0';

                if (strlen(input) == 0) continue;

                if (send_encrypted(sock, (unsigned char *)input) < 0) break;
                if (recv_encrypted(sock, reply, sizeof(reply)) < 0) break;

                printf("Server: %s\n", reply);

                if (strcmp(input, "endchat") == 0) break;
            }
            continue;
        }

        if (sscanf(input, "upload %255s", fname) == 1) {
            if (access_level < 3) {
                printf("[DENIED] upload requires Top Level access.\n");
                continue;
            }

            if (send_encrypted(sock, (unsigned char *)input) < 0) break;
            if (recv_encrypted(sock, reply, sizeof(reply)) < 0) break;

            printf("Server: %s\n", reply);

            FILE *fp = fopen(fname, "r");
            if (!fp) {
                printf("[ERROR] Local file not found: %s\n", fname);
                send_encrypted(sock, (unsigned char *)"[EMPTY]");
            } else {
                char content[BUFFER_SIZE];
                content[0] = '\0';
                char tmp[256];

                while (fgets(tmp, sizeof(tmp), fp))
                    strncat(content, tmp, sizeof(content) - strlen(content) - 1);

                fclose(fp);
                send_encrypted(sock, (unsigned char *)content);
            }

            if (recv_encrypted(sock, reply, sizeof(reply)) < 0) break;
            printf("Server: %s\n", reply);
            continue;
        }

        if (sscanf(input, "download %255s", fname) == 1) {
            if (access_level < 3) {
                printf("[DENIED] download requires Top Level access.\n");
                continue;
            }

            if (send_encrypted(sock, (unsigned char *)input) < 0) break;
            if (recv_encrypted(sock, reply, sizeof(reply)) < 0) break;

            if (strncmp((char *)reply, "[ERROR]", 7) == 0 ||
                strncmp((char *)reply, "[DENIED]", 8) == 0) {
                printf("Server: %s\n", reply);
                continue;
            }

            FILE *fp = fopen(fname, "w");
            if (fp) {
                fprintf(fp, "%s", (char *)reply);
                fclose(fp);
                printf("[OK] File saved locally as: %s\n", fname);
            } else {
                printf("Server content:\n%s\n", reply);
            }
            continue;
        }

        if (strcmp(input, "exit") == 0) {
            send_encrypted(sock, (unsigned char *)"exit");
            printf("Disconnected.\n");
            break;
        }

        if (send_encrypted(sock, (unsigned char *)input) < 0) {
            perror("send");
            break;
        }

        if (recv_encrypted(sock, reply, sizeof(reply)) < 0) {
            perror("recv");
            break;
        }

        printf("Server: %s\n", reply);
    }

    close(sock);
    return 0;
}
