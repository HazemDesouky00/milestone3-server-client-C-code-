#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/aes.h>
#include <sys/stat.h>
#include <errno.h>

#define PORT 8080
#define BUFFER_SIZE 4096
#define AES_KEY_SIZE 16

#define LEVEL_ENTRY  1
#define LEVEL_MEDIUM 2
#define LEVEL_TOP    3

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
    int net = htonl(padded_len);
    if (send_all(sock, &net, sizeof(net)) < 0) return -1;
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
    printf("[Encrypted received] ");
    for (int i = 0; i < clen; i++) printf("%02X ", cipher[i]);
    printf("\n");
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

int parse_level(const char *role) {
    if (strcasecmp(role, "top")    == 0) return LEVEL_TOP;
    if (strcasecmp(role, "medium") == 0) return LEVEL_MEDIUM;
    return LEVEL_ENTRY;
}

int authenticate_and_get_level(const char *credentials, int *level_out) {
    char uname[128], upass[128];
    if (sscanf(credentials, "%127[^:]:%127s", uname, upass) != 2) return 0;

    FILE *f = fopen("users.txt", "r");
    if (!f) { perror("users.txt"); return 0; }

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = '\0';
        char fu[128], fp[128], role[32];
        int fields = sscanf(line, "%127[^:]:%127[^:]:%31s", fu, fp, role);
        if (fields < 2) continue;
        if (fields == 2) strcpy(role, "entry");
        if (strcmp(fu, uname) == 0 && strcmp(fp, upass) == 0) {
            *level_out = parse_level(role);
            fclose(f);
            return 1;
        }
    }
    fclose(f);
    return 0;
}

int is_allowed(int level, const char *cmd_type) {
    if (strcmp(cmd_type, "basic")    == 0) return level >= LEVEL_ENTRY;
    if (strcmp(cmd_type, "read")     == 0) return level >= LEVEL_MEDIUM;
    if (strcmp(cmd_type, "write")    == 0) return level >= LEVEL_MEDIUM;
    if (strcmp(cmd_type, "delete")   == 0) return level >= LEVEL_TOP;
    if (strcmp(cmd_type, "transfer") == 0) return level >= LEVEL_TOP;
    return 0;
}

void dispatch_command(int sock, int level, const char *cmd) {
    char response[BUFFER_SIZE];
    char arg1[256] = {0}, arg2[256] = {0};

    if (strcmp(cmd, "whoami") == 0) {
        const char *name = (level == LEVEL_TOP)   ? "Top Level"    :
                           (level == LEVEL_MEDIUM) ? "Medium Level" : "Entry Level";
        snprintf(response, sizeof(response), "[INFO] Logged in as: %s (level %d)", name, level);
        send_encrypted(sock, (unsigned char *)response);
        return;
    }

    if (strcmp(cmd, "ls") == 0) {
        if (!is_allowed(level, "basic")) {
            send_encrypted(sock, (unsigned char *)"[DENIED] ls requires Entry level or above.");
            return;
        }
        FILE *p = popen("ls -la 2>&1", "r");
        if (!p) { send_encrypted(sock, (unsigned char *)"[ERROR] popen failed"); return; }
        response[0] = '\0';
        char tmp[256];
        while (fgets(tmp, sizeof(tmp), p))
            strncat(response, tmp, sizeof(response) - strlen(response) - 1);
        pclose(p);
        send_encrypted(sock, (unsigned char *)response);
        return;
    }

    if (sscanf(cmd, "cat %255s", arg1) == 1) {
        if (!is_allowed(level, "basic")) {
            send_encrypted(sock, (unsigned char *)"[DENIED] cat requires Entry level or above.");
            return;
        }
        FILE *fp = fopen(arg1, "r");
        if (!fp) {
            snprintf(response, sizeof(response), "[ERROR] Cannot open: %s", arg1);
            send_encrypted(sock, (unsigned char *)response);
            return;
        }
        response[0] = '\0';
        char tmp[256];
        while (fgets(tmp, sizeof(tmp), fp))
            strncat(response, tmp, sizeof(response) - strlen(response) - 1);
        fclose(fp);
        send_encrypted(sock, (unsigned char *)response);
        return;
    }

    if (sscanf(cmd, "read %255s", arg1) == 1) {
        if (!is_allowed(level, "read")) {
            send_encrypted(sock, (unsigned char *)"[DENIED] read requires Medium level or above.");
            return;
        }
        FILE *fp = fopen(arg1, "r");
        if (!fp) {
            snprintf(response, sizeof(response), "[ERROR] Cannot open: %s", arg1);
            send_encrypted(sock, (unsigned char *)response);
            return;
        }
        response[0] = '\0';
        char tmp[256];
        while (fgets(tmp, sizeof(tmp), fp))
            strncat(response, tmp, sizeof(response) - strlen(response) - 1);
        fclose(fp);
        send_encrypted(sock, (unsigned char *)response);
        return;
    }

    if (sscanf(cmd, "copy %255s %255s", arg1, arg2) == 2) {
        if (!is_allowed(level, "write")) {
            send_encrypted(sock, (unsigned char *)"[DENIED] copy requires Medium level or above.");
            return;
        }
        FILE *src = fopen(arg1, "rb");
        if (!src) {
            snprintf(response, sizeof(response), "[ERROR] Source not found: %s", arg1);
            send_encrypted(sock, (unsigned char *)response);
            return;
        }
        FILE *dst = fopen(arg2, "wb");
        if (!dst) {
            fclose(src);
            snprintf(response, sizeof(response), "[ERROR] Cannot create: %s", arg2);
            send_encrypted(sock, (unsigned char *)response);
            return;
        }
        char buf[512]; size_t n;
        while ((n = fread(buf, 1, sizeof(buf), src)) > 0)
            fwrite(buf, 1, n, dst);
        fclose(src); fclose(dst);
        snprintf(response, sizeof(response), "[OK] Copied %s -> %s", arg1, arg2);
        send_encrypted(sock, (unsigned char *)response);
        return;
    }

    if (sscanf(cmd, "edit %255s %4031[^\n]", arg1, arg2) >= 1) {
        if (!is_allowed(level, "write")) {
            send_encrypted(sock, (unsigned char *)"[DENIED] edit requires Medium level or above.");
            return;
        }
        FILE *fp = fopen(arg1, "w");
        if (!fp) {
            snprintf(response, sizeof(response), "[ERROR] Cannot write: %s", arg1);
            send_encrypted(sock, (unsigned char *)response);
            return;
        }
        fprintf(fp, "%s\n", arg2);
        fclose(fp);
        snprintf(response, sizeof(response), "[OK] %s updated.", arg1);
        send_encrypted(sock, (unsigned char *)response);
        return;
    }

    if (sscanf(cmd, "delete %255s", arg1) == 1) {
        if (!is_allowed(level, "delete")) {
            send_encrypted(sock, (unsigned char *)"[DENIED] delete requires Top level.");
            return;
        }
        if (remove(arg1) == 0)
            snprintf(response, sizeof(response), "[OK] Deleted %s", arg1);
        else
            snprintf(response, sizeof(response), "[ERROR] Cannot delete %s: %s", arg1, strerror(errno));
        send_encrypted(sock, (unsigned char *)response);
        return;
    }

    if (sscanf(cmd, "upload %255s", arg1) == 1) {
        if (!is_allowed(level, "transfer")) {
            send_encrypted(sock, (unsigned char *)"[DENIED] upload requires Top level.");
            return;
        }
        send_encrypted(sock, (unsigned char *)"[READY] Send file content:");
        unsigned char content[BUFFER_SIZE];
        if (recv_encrypted(sock, content, sizeof(content)) < 0) {
            send_encrypted(sock, (unsigned char *)"[ERROR] Failed to receive content.");
            return;
        }
        FILE *fp = fopen(arg1, "w");
        if (!fp) {
            send_encrypted(sock, (unsigned char *)"[ERROR] Cannot create file on server.");
            return;
        }
        fprintf(fp, "%s", (char *)content);
        fclose(fp);
        snprintf(response, sizeof(response), "[OK] %s uploaded to server.", arg1);
        send_encrypted(sock, (unsigned char *)response);
        return;
    }

    if (sscanf(cmd, "download %255s", arg1) == 1) {
        if (!is_allowed(level, "transfer")) {
            send_encrypted(sock, (unsigned char *)"[DENIED] download requires Top level.");
            return;
        }
        FILE *fp = fopen(arg1, "r");
        if (!fp) {
            snprintf(response, sizeof(response), "[ERROR] File not found: %s", arg1);
            send_encrypted(sock, (unsigned char *)response);
            return;
        }
        response[0] = '\0';
        char tmp[256];
        while (fgets(tmp, sizeof(tmp), fp))
            strncat(response, tmp, sizeof(response) - strlen(response) - 1);
        fclose(fp);
        send_encrypted(sock, (unsigned char *)response);
        return;
    }

    if (strcmp(cmd, "chat") == 0) {
        send_encrypted(sock, (unsigned char *)"[CHAT] Entering chat mode. Type 'endchat' to exit.");
        unsigned char chat_msg[BUFFER_SIZE];
        while (1) {
            if (recv_encrypted(sock, chat_msg, sizeof(chat_msg)) < 0) break;
            if (strcmp((char *)chat_msg, "endchat") == 0) {
                send_encrypted(sock, (unsigned char *)"[CHAT] Exiting chat mode.");
                break;
            }
            printf("[Thread %lu] Chat: %s\n", pthread_self(), chat_msg);
            send_encrypted(sock, chat_msg);
        }
        return;
    }

    snprintf(response, sizeof(response),
        "[ERROR] Unknown command: '%s' | type 'chat' for free chat mode", cmd);
    send_encrypted(sock, (unsigned char *)response);
}

void *handle_client(void *arg) {
    int csock = *((int *)arg);
    free(arg);

    char credentials[256];
    unsigned char cmd[BUFFER_SIZE];
    int level = 0;

    if (recv_string(csock, credentials, sizeof(credentials)) < 0) {
        printf("[Thread %lu] Failed to receive credentials\n", pthread_self());
        close(csock); pthread_exit(NULL);
    }
    printf("[Thread %lu] Auth attempt: %s\n", pthread_self(), credentials);

    if (!authenticate_and_get_level(credentials, &level)) {
        send_string(csock, "AUTH_FAIL");
        printf("[Thread %lu] Auth failed\n", pthread_self());
        close(csock); pthread_exit(NULL);
    }

    const char *role_name = (level == LEVEL_TOP)   ? "top"    :
                            (level == LEVEL_MEDIUM) ? "medium" : "entry";
    char ok_msg[32];
    snprintf(ok_msg, sizeof(ok_msg), "AUTH_OK|%s", role_name);
    send_string(csock, ok_msg);
    printf("[Thread %lu] Auth OK - role: %s\n", pthread_self(), role_name);

    while (1) {
        int res = recv_encrypted(csock, cmd, sizeof(cmd));
        if (res < 0) {
            printf("[Thread %lu] Client disconnected\n", pthread_self());
            break;
        }
        printf("[Thread %lu] Command: %s\n", pthread_self(), cmd);
        if (strcmp((char *)cmd, "exit") == 0) break;
        dispatch_command(csock, level, (char *)cmd);
    }

    close(csock);
    printf("[Thread %lu] Thread closing\n", pthread_self());
    pthread_exit(NULL);
}

int main() {
    int server_fd;
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); exit(EXIT_FAILURE); }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        { perror("bind"); exit(EXIT_FAILURE); }
    if (listen(server_fd, 10) < 0)
        { perror("listen"); exit(EXIT_FAILURE); }

    printf("MS3 Server listening on port %d...\n", PORT);

    while (1) {
        int *csock = malloc(sizeof(int));
        if (!csock) { perror("malloc"); continue; }
        *csock = accept(server_fd, (struct sockaddr *)&addr, &addrlen);
        if (*csock < 0) { perror("accept"); free(csock); continue; }
        printf("[Main] New client connected\n");
        pthread_t tid;
        if (pthread_create(&tid, NULL, handle_client, csock) != 0) {
            perror("pthread_create"); close(*csock); free(csock); continue;
        }
        pthread_detach(tid);
    }

    close(server_fd);
    return 0;
}
