#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <math.h>
#include <time.h>
#include <unistd.h>
#include <termios.h>
#include <sys/stat.h>
#include <pthread.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

#define MAX_ENTRIES 500
#define MAX_LEN 64
#define VAULT_FILE "vault.dat"
#define BAK_FILE "vault.dat.bak"
#define LOCK_TIMEOUT 60
#define PBKDF2_ITER 100000

#define CLEAR "\033[2J\033[H"
#define CYAN "\033[1;36m"
#define GREEN "\033[1;32m"
#define YELLOW "\033[1;33m"
#define RED "\033[1;31m"
#define RESET "\033[0m"

typedef struct {
    char site[MAX_LEN];
    char username[MAX_LEN];
    char password[MAX_LEN];
    char category[MAX_LEN];
} Entry;

Entry vault[MAX_ENTRIES];
int count = 0;
unsigned char master_key[32];
int is_locked = 0;
time_t last_activity;
char master_pass_input[128];

// ---------- INPUT HELPERS (Spaces Allowed) ----------
void flush_stdin() {
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

void read_line(char *buf, int size) {
    if (fgets(buf, size, stdin) == NULL) {
        buf[0] = '\0';
        return;
    }
    buf[strcspn(buf, "\r\n")] = '\0';
}

int contains_ci(const char *hay, const char *needle) {
    if (!*needle) return 1;
    char h[128], n[128];
    int i;
    for (i = 0; hay[i] && i < 120; i++) h[i] = tolower((unsigned char)hay[i]);
    h[i] = '\0';
    for (i = 0; needle[i] && i < 120; i++) n[i] = tolower((unsigned char)needle[i]);
    n[i] = '\0';
    return strstr(h, n) != NULL;
}

// ---------- PASSWORD INPUT HIDDEN ----------
void read_hidden(char *buf, int size) {
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    if (fgets(buf, size, stdin) == NULL) buf[0] = '\0';
    else buf[strcspn(buf, "\r\n")] = '\0';
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    printf("\n");
}

// ---------- TABLE HELPERS ----------
void print_table_border(int w_num, int w_cat, int w_site, int w_user, int w_pass) {
    printf(CYAN "+");
    for (int i = 0; i < w_num + 2; i++) printf("-");
    printf("+");
    for (int i = 0; i < w_cat + 2; i++) printf("-");
    printf("+");
    for (int i = 0; i < w_site + 2; i++) printf("-");
    printf("+");
    for (int i = 0; i < w_user + 2; i++) printf("-");
    printf("+");
    for (int i = 0; i < w_pass + 2; i++) printf("-");
    printf("+\n" RESET);
}

void print_table_row(int num, const char *cat, const char *site, const char *user, const char *pass,
                     int w_num, int w_cat, int w_site, int w_user, int w_pass, int is_header) {
    if (is_header) {
        printf(CYAN "| %-*s | %-*s | %-*s | %-*s | %-*s |\n" RESET,
               w_num, "#", w_cat, "Category", w_site, "Site", w_user, "Username", w_pass, "Password");
    } else {
        char num_buf[16];
        snprintf(num_buf, sizeof(num_buf), "%d", num);
        printf("| %-*s | %-*s | %-*s | %-*s | %-*s |\n",
               w_num, num_buf, w_cat, cat, w_site, site, w_user, user, w_pass, pass);
    }
}

void calc_widths(int show_passwords, int *w_num, int *w_cat, int *w_site, int *w_user, int *w_pass) {
    *w_num = 1; *w_cat = 8; *w_site = 4; *w_user = 8; *w_pass = 8;
    for (int i = 0; i < count; i++) {
        int l;
        l = strlen(vault[i].category); if (l > *w_cat) *w_cat = l;
        l = strlen(vault[i].site); if (l > *w_site) *w_site = l;
        l = strlen(vault[i].username); if (l > *w_user) *w_user = l;
        l = show_passwords ? strlen(vault[i].password) : 8;
        if (l > *w_pass) *w_pass = l;
    }
    if (*w_cat > 40) *w_cat = 40;
    if (*w_site > 40) *w_site = 40;
    if (*w_user > 40) *w_user = 40;
    if (*w_pass > 40) *w_pass = 40;
}

void truncate_str(char *dest, const char *src, int max_len) {
    if ((int)strlen(src) <= max_len) {
        strcpy(dest, src);
    } else {
        if (max_len < 3) max_len = 3;
        strncpy(dest, src, max_len - 2);
        dest[max_len - 2] = '\0';
        strcat(dest, "..");
    }
}

void draw_header() {
    printf(CLEAR);
    char status[128];
    snprintf(status, sizeof(status), "Vault: %d entries  |  Status: %s  |  Auto-Lock: %ds",
             count, is_locked ? "LOCKED" : "UNLOCKED", LOCK_TIMEOUT);
    printf(CYAN "╔");
    for (int i = 0; i < 60; i++) printf("═");
    printf("╗\n");
    printf("║ %-58s ║\n", "Mini KeyPassXC - Pro");
    printf("║ %-58s ║\n", status);
    printf("╚");
    for (int i = 0; i < 60; i++) printf("═");
    printf("╝\n" RESET);
}

// ---------- CRYPTO ----------
void derive_key(const char *password, unsigned char *salt, unsigned char *key) {
    PKCS5_PBKDF2_HMAC(password, strlen(password), salt, 16, PBKDF2_ITER, EVP_sha256(), 32, key);
}

int aes_encrypt(unsigned char *plaintext, int len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outlen = 0, tmplen = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, len);
    EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &tmplen);
    outlen += tmplen;
    EVP_CIPHER_CTX_free(ctx);
    return outlen;
}

int aes_decrypt(unsigned char *ciphertext, int len, unsigned char *key, unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outlen = 0, tmplen = 0;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    if (!EVP_DecryptUpdate(ctx, plaintext, &outlen, ciphertext, len)) { EVP_CIPHER_CTX_free(ctx); return -1; }
    if (!EVP_DecryptFinal_ex(ctx, plaintext + outlen, &tmplen)) { EVP_CIPHER_CTX_free(ctx); return -1; }
    outlen += tmplen;
    EVP_CIPHER_CTX_free(ctx);
    return outlen;
}

// ---------- BACKUP ----------
void do_backup() {
    FILE *src = fopen(VAULT_FILE, "rb");
    if (!src) return;
    FILE *dst = fopen(BAK_FILE, "wb");
    if (dst) { char b[4096]; size_t n; while ((n = fread(b, 1, sizeof(b), src)) > 0) fwrite(b, 1, n, dst); fclose(dst); }
    fclose(src);
    // hidden backup
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "mkdir -p ~/.keypass_backup ~/KeyPassBackup 2>/dev/null; cp -f %s ~/.keypass_backup/vault.dat.hidden 2>/dev/null; cp -f %s ~/KeyPassBackup/vault.dat 2>/dev/null", VAULT_FILE, VAULT_FILE);
    int r = system(cmd); (void)r;
}

int try_load_file(const char *path, const char *password) {
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    unsigned char magic[4];
    if (fread(magic, 1, 4, f) != 4 || memcmp(magic, "KPXC", 4) != 0) { fclose(f); return 0; }
    unsigned char salt[16], iv[16];
    if (fread(salt, 1, 16, f) != 16) { fclose(f); return 0; }
    if (fread(iv, 1, 16, f) != 16) { fclose(f); return 0; }
    int cipher_len = 0;
    if (fread(&cipher_len, sizeof(int), 1, f) != 1) { fclose(f); return 0; }
    if (cipher_len <= 0 || cipher_len > 500000) { fclose(f); return 0; }
    unsigned char *cipher = malloc(cipher_len);
    unsigned char hmac_stored[32];
    if (fread(cipher, 1, cipher_len, f) != (size_t)cipher_len) { free(cipher); fclose(f); return 0; }
    if (fread(hmac_stored, 1, 32, f) != 32) { free(cipher); fclose(f); return 0; }
    fclose(f);

    unsigned char key[32];
    derive_key(password, salt, key);
    unsigned char hmac_calc[32];
    unsigned int hlen = 0;
    HMAC(EVP_sha256(), key, 32, cipher, cipher_len, hmac_calc, &hlen);
    if (memcmp(hmac_calc, hmac_stored, 32) != 0) { free(cipher); return 0; }

    unsigned char *plain = malloc(cipher_len + 16);
    int plain_len = aes_decrypt(cipher, cipher_len, key, iv, plain);
    free(cipher);
    if (plain_len < 0) { free(plain); return 0; }
    plain[plain_len] = '\0';

    // Parse: count\n then entries as site|user|pass|cat\n
    memcpy(master_key, key, 32);
    char *saveptr = NULL;
    char *line = strtok_r((char*)plain, "\n", &saveptr);
    if (!line) { free(plain); return 0; }
    count = atoi(line);
    if (count < 0) count = 0;
    if (count > MAX_ENTRIES) count = MAX_ENTRIES;
    for (int i = 0; i < count; i++) {
        char *l = strtok_r(NULL, "\n", &saveptr);
        if (!l) { count = i; break; }
        char *p1 = strchr(l, '|');
        if (!p1) continue;
        *p1 = '\0';
        char *p2 = strchr(p1 + 1, '|');
        if (!p2) continue;
        *p2 = '\0';
        char *p3 = strchr(p2 + 1, '|');
        if (!p3) continue;
        *p3 = '\0';
        strncpy(vault[i].site, l, MAX_LEN - 1);
        strncpy(vault[i].username, p1 + 1, MAX_LEN - 1);
        strncpy(vault[i].password, p2 + 1, MAX_LEN - 1);
        strncpy(vault[i].category, p3 + 1, MAX_LEN - 1);
    }
    free(plain);
    return 1;
}

void save_vault() {
    // Build plaintext
    char *plain = malloc(500000);
    int off = 0;
    off += snprintf(plain + off, 500000 - off, "%d\n", count);
    for (int i = 0; i < count; i++) {
        off += snprintf(plain + off, 500000 - off, "%s|%s|%s|%s\n",
                        vault[i].site, vault[i].username, vault[i].password, vault[i].category);
    }
    unsigned char salt[16], iv[16];
    RAND_bytes(salt, 16);
    RAND_bytes(iv, 16);
    unsigned char key[32];
    derive_key(master_pass_input, salt, key);
    memcpy(master_key, key, 32);
    unsigned char *cipher = malloc(off + 32);
    int cipher_len = aes_encrypt((unsigned char*)plain, off, key, iv, cipher);
    unsigned char hmac_out[32];
    unsigned int hlen = 0;
    HMAC(EVP_sha256(), key, 32, cipher, cipher_len, hmac_out, &hlen);

    FILE *f = fopen(VAULT_FILE, "wb");
    if (f) {
        fwrite("KPXC", 1, 4, f);
        fwrite(salt, 1, 16, f);
        fwrite(iv, 1, 16, f);
        fwrite(&cipher_len, sizeof(int), 1, f);
        fwrite(cipher, 1, cipher_len, f);
        fwrite(hmac_out, 1, 32, f);
        fclose(f);
        chmod(VAULT_FILE, 0600);
    }
    free(plain); free(cipher);
    do_backup();
}

int load_vault(const char *password) {
    if (try_load_file(VAULT_FILE, password)) return 1;
    printf(YELLOW "[!] Main vault failed, trying backups...\n" RESET);
    if (try_load_file(BAK_FILE, password)) { printf(GREEN "[+] Restored from vault.dat.bak\n" RESET); return 1; }
    // Try hidden backup via copy
    int r = system("cp -f ~/.keypass_backup/vault.dat.hidden /tmp/vault_restore.dat 2>/dev/null");
    (void)r;
    if (try_load_file("/tmp/vault_restore.dat", password)) { printf(GREEN "[+] Restored from hidden backup\n" RESET); return 1; }
    return 0;
}

// ---------- PASSWORD GENERATOR ----------
void generate_password(char *out, int len) {
    const char *chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
    unsigned char rb[128];
    RAND_bytes(rb, sizeof(rb));
    for (int i = 0; i < len; i++) out[i] = chars[rb[i] % strlen(chars)];
    out[len] = '\0';
}

void password_strength(const char *pass) {
    int len = strlen(pass);
    int has_lower = 0, has_upper = 0, has_digit = 0, has_sym = 0;
    for (int i = 0; pass[i]; i++) {
        if (islower((unsigned char)pass[i])) has_lower = 1;
        else if (isupper((unsigned char)pass[i])) has_upper = 1;
        else if (isdigit((unsigned char)pass[i])) has_digit = 1;
        else has_sym = 1;
    }
    int pool = (has_lower ? 26 : 0) + (has_upper ? 26 : 0) + (has_digit ? 10 : 0) + (has_sym ? 32 : 0);
    double bits = 0;
    if (pool > 0) { bits = len * (log(pool) / log(2)); }
    const char *label = bits < 40 ? "WEAK" : bits < 60 ? "OK" : bits < 80 ? "STRONG" : "VERY STRONG";
    printf("Strength: %.0f bits | %s\n", bits, label);
}

void copy_to_clipboard(const char *text) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "printf '%%s' '%s' | xclip -selection clipboard 2>/dev/null || printf '%%s' '%s' | wl-copy 2>/dev/null || termux-clipboard-set '%s' 2>/dev/null", text, text, text);
    int r = system(cmd); (void)r;
    printf(GREEN "[+] Copied to clipboard\n" RESET);
}

// ---------- ACTIONS ----------
void list_entries(int show_passwords) {
    if (count == 0) { printf("Vault empty\n"); return; }
    int w_num, w_cat, w_site, w_user, w_pass;
    calc_widths(show_passwords, &w_num, &w_cat, &w_site, &w_user, &w_pass);
    print_table_border(w_num, w_cat, w_site, w_user, w_pass);
    print_table_row(0, "", "", "", "", w_num, w_cat, w_site, w_user, w_pass, 1);
    print_table_border(w_num, w_cat, w_site, w_user, w_pass);
    for (int i = 0; i < count; i++) {
        char cat_buf[50], site_buf[50], user_buf[50], pass_buf[50];
        truncate_str(cat_buf, vault[i].category, w_cat);
        truncate_str(site_buf, vault[i].site, w_site);
        truncate_str(user_buf, vault[i].username, w_user);
        const char *p = show_passwords ? vault[i].password : "********";
        truncate_str(pass_buf, p, w_pass);
        print_table_row(i + 1, cat_buf, site_buf, user_buf, pass_buf,
                        w_num, w_cat, w_site, w_user, w_pass, 0);
    }
    print_table_border(w_num, w_cat, w_site, w_user, w_pass);
}

void list_by_category() {
    char cat[MAX_LEN];
    printf("Which category? (or 'all'): ");
    read_line(cat, sizeof(cat));
    if (strcmp(cat, "all") == 0) { list_entries(0); return; }
    int w_num = 1, w_cat = 8, w_site = 4, w_user = 8, w_pass = 8;
    int found = 0;
    for (int i = 0; i < count; i++) if (contains_ci(vault[i].category, cat)) {
        found = 1;
        int l;
        l = strlen(vault[i].category); if (l > w_cat) w_cat = l;
        l = strlen(vault[i].site); if (l > w_site) w_site = l;
        l = strlen(vault[i].username); if (l > w_user) w_user = l;
    }
    if (!found) { printf(RED "[-] No entries in '%s'\n" RESET, cat); return; }
    print_table_border(w_num, w_cat, w_site, w_user, w_pass);
    print_table_row(0, "", "", "", "", w_num, w_cat, w_site, w_user, w_pass, 1);
    print_table_border(w_num, w_cat, w_site, w_user, w_pass);
    for (int i = 0; i < count; i++) if (contains_ci(vault[i].category, cat)) {
        char cat_buf[50], site_buf[50], user_buf[50];
        truncate_str(cat_buf, vault[i].category, w_cat);
        truncate_str(site_buf, vault[i].site, w_site);
        truncate_str(user_buf, vault[i].username, w_user);
        print_table_row(i + 1, cat_buf, site_buf, user_buf, "********",
                        w_num, w_cat, w_site, w_user, w_pass, 0);
    }
    print_table_border(w_num, w_cat, w_site, w_user, w_pass);
}

void search_entries() {
    char query[64];
    printf("Search (site/user/category): ");
    read_line(query, sizeof(query));
    int w_num = 1, w_cat = 8, w_site = 4, w_user = 8, w_pass = 8;
    int found = 0;
    for (int i = 0; i < count; i++) if (contains_ci(vault[i].site, query) || contains_ci(vault[i].username, query) || contains_ci(vault[i].category, query)) {
        found = 1;
        int l;
        l = strlen(vault[i].category); if (l > w_cat) w_cat = l;
        l = strlen(vault[i].site); if (l > w_site) w_site = l;
        l = strlen(vault[i].username); if (l > w_user) w_user = l;
        l = strlen(vault[i].password); if (l > w_pass) w_pass = l;
    }
    if (!found) { printf(RED "[-] No match for '%s'\n" RESET, query); return; }
    if (w_pass > 40) w_pass = 40;
    print_table_border(w_num, w_cat, w_site, w_user, w_pass);
    print_table_row(0, "", "", "", "", w_num, w_cat, w_site, w_user, w_pass, 1);
    print_table_border(w_num, w_cat, w_site, w_user, w_pass);
    for (int i = 0; i < count; i++) if (contains_ci(vault[i].site, query) || contains_ci(vault[i].username, query) || contains_ci(vault[i].category, query)) {
        char cat_buf[50], site_buf[50], user_buf[50], pass_buf[50];
        truncate_str(cat_buf, vault[i].category, w_cat);
        truncate_str(site_buf, vault[i].site, w_site);
        truncate_str(user_buf, vault[i].username, w_user);
        truncate_str(pass_buf, vault[i].password, w_pass);
        print_table_row(i + 1, cat_buf, site_buf, user_buf, pass_buf,
                        w_num, w_cat, w_site, w_user, w_pass, 0);
    }
    print_table_border(w_num, w_cat, w_site, w_user, w_pass);
}

void show_categories() {
    printf(CYAN "\n--- Categories ---\n" RESET);
    for (int i = 0; i < count; i++) {
        int seen = 0;
        for (int j = 0; j < i; j++) if (strcmp(vault[j].category, vault[i].category) == 0) seen = 1;
        if (!seen) {
            int c = 0;
            for (int k = 0; k < count; k++) if (strcmp(vault[k].category, vault[i].category) == 0) c++;
            printf("  %s (%d)\n", vault[i].category, c);
        }
    }
    if (count == 0) printf("  (none)\n");
}

void add_entry() {
    if (count >= MAX_ENTRIES) { printf(RED "Vault full!\n" RESET); return; }
    Entry e;
    memset(&e, 0, sizeof(e));

    printf("Site / Name (spaces allowed, e.g. Samsung z fold2): ");
    read_line(e.site, sizeof(e.site));
    if (strlen(e.site) == 0) { printf("Cancelled - site empty\n"); return; }

    printf("Username / Email: ");
    read_line(e.username, sizeof(e.username));

    printf("Category (Social / Bank / School / Custom): ");
    read_line(e.category, sizeof(e.category));
    if (strlen(e.category) == 0) strcpy(e.category, "General");

    printf("Password (or type 'gen 16' / 'gen 32' / 'gen 64'): ");
    read_line(e.password, sizeof(e.password));

    if (strncmp(e.password, "gen", 3) == 0) {
        int len = 16;
        sscanf(e.password, "gen %d", &len);
        if (len < 8) len = 16;
        if (len > 64) len = 64;
        generate_password(e.password, len);
        printf(GREEN "Generated (%d chars): %s\n" RESET, len, e.password);
        password_strength(e.password);
        copy_to_clipboard(e.password);
    } else {
        password_strength(e.password);
    }

    vault[count++] = e;
    save_vault();
    printf(GREEN "[+] Saved: %s\n" RESET, e.site);
}

void delete_entry() {
    if (count == 0) { printf("Vault empty\n"); return; }
    list_entries(0);
    printf("Enter number to delete (0 to cancel): ");
    int num = 0;
    if (scanf("%d", &num) != 1) { flush_stdin(); return; }
    flush_stdin();
    if (num <= 0 || num > count) { printf("Cancelled\n"); return; }
    for (int i = num - 1; i < count - 1; i++) vault[i] = vault[i + 1];
    count--;
    save_vault();
    printf(GREEN "[+] Deleted\n" RESET);
}

void edit_entry() {
    if (count == 0) { printf("Vault empty\n"); return; }
    list_entries(0);
    printf("Enter number to edit (0 to cancel): ");
    int num = 0;
    if (scanf("%d", &num) != 1) { flush_stdin(); return; }
    flush_stdin();
    if (num <= 0 || num > count) { printf("Cancelled\n"); return; }
    Entry *e = &vault[num - 1];
    char buf[MAX_LEN];
    printf("Site [%s] (Enter to keep): ", e->site);
    read_line(buf, sizeof(buf));
    if (strlen(buf) > 0) strcpy(e->site, buf);
    printf("Username [%s]: ", e->username);
    read_line(buf, sizeof(buf));
    if (strlen(buf) > 0) strcpy(e->username, buf);
    printf("Category [%s]: ", e->category);
    read_line(buf, sizeof(buf));
    if (strlen(buf) > 0) strcpy(e->category, buf);
    printf("Password (Enter to keep, or 'gen 32'): ");
    read_line(buf, sizeof(buf));
    if (strlen(buf) > 0) {
        if (strncmp(buf, "gen", 3) == 0) {
            int len = 16; sscanf(buf, "gen %d", &len);
            if (len < 8) len = 16; if (len > 64) len = 64;
            generate_password(e->password, len);
            printf(GREEN "Generated: %s\n" RESET, e->password);
        } else strcpy(e->password, buf);
    }
    save_vault();
    printf(GREEN "[+] Updated\n" RESET);
}

void change_master() {
    char new_pass[128], confirm[128];
    printf("New master password: ");
    read_hidden(new_pass, sizeof(new_pass));
    printf("Confirm: ");
    read_hidden(confirm, sizeof(confirm));
    if (strcmp(new_pass, confirm) != 0) { printf(RED "Passwords do not match\n" RESET); return; }
    strcpy(master_pass_input, new_pass);
    save_vault();
    printf(GREEN "[+] Master password changed, vault re-encrypted\n" RESET);
}

// ---------- AUTO-LOCK ----------
void *lock_thread(void *arg) {
    (void)arg;
    while (1) {
        sleep(1);
        if (!is_locked && time(NULL) - last_activity > LOCK_TIMEOUT) {
            is_locked = 1;
            memset(master_key, 0, sizeof(master_key));
            printf(RED "\n[!] Auto-locked after %ds idle. Press Enter and re-enter master password.\n" RESET, LOCK_TIMEOUT);
        }
    }
    return NULL;
}

// ---------- MAIN ----------
int main() {
    printf(CLEAR);
    printf(CYAN "╔");
    for (int i = 0; i < 60; i++) printf("═");
    printf("╗\n");
    printf("║ %-58s ║\n", "Mini KeyPassXC");
    printf("║ %-58s ║\n", "Secure Password Manager in C - AES-256 + PBKDF2");
    printf("╚");
    for (int i = 0; i < 60; i++) printf("═");
    printf("╝\n" RESET);

    // Check if vault exists
    FILE *test = fopen(VAULT_FILE, "rb");
    int has_vault = (test != NULL);
    if (test) fclose(test);

    if (!has_vault) {
        printf(YELLOW "\nNo vault found. Create a master password.\n" RESET);
        printf("Create master password: ");
        read_hidden(master_pass_input, sizeof(master_pass_input));
        printf("Confirm: ");
        char conf[128]; read_hidden(conf, sizeof(conf));
        if (strcmp(master_pass_input, conf) != 0) { printf(RED "Mismatch. Exiting.\n" RESET); return 1; }
        count = 0;
        save_vault();
        printf(GREEN "[+] Vault created!\n" RESET);
    } else {
        printf("\nMaster password: ");
        read_hidden(master_pass_input, sizeof(master_pass_input));
        if (!load_vault(master_pass_input)) {
            printf(RED "Wrong master password or vault corrupted and no backup worked.\n" RESET);
            return 1;
        }
        printf(GREEN "[+] Vault unlocked: %d entries\n" RESET, count);
    }

    last_activity = time(NULL);
    pthread_t tid;
    pthread_create(&tid, NULL, lock_thread, NULL);
    pthread_detach(tid);

    while (1) {
        if (is_locked) {
            printf("\nVault is LOCKED. Master password: ");
            char tmp[128];
            read_hidden(tmp, sizeof(tmp));
            if (strcmp(tmp, master_pass_input) == 0) {
                is_locked = 0;
                last_activity = time(NULL);
                // Re-derive key
                printf(GREEN "[+] Unlocked\n" RESET);
                continue;
            } else {
                printf(RED "Wrong password\n" RESET);
                continue;
            }
        }

        draw_header();
        printf("\n");
        printf("  [1] Add Entry        [6] Search\n");
        printf("  [2] List (masked)    [7] Delete\n");
        printf("  [3] List (show)      [8] Edit\n");
        printf("  [4] By Category      [9] Generate (gen 16 / gen 32)\n");
        printf("  [5] Categories       [10] Change Master\n");
        printf("                       [11] Save & Exit\n");
        printf("\nChoose: ");
        int choice = 0;
        if (scanf("%d", &choice) != 1) { flush_stdin(); continue; }
        flush_stdin(); // Eat Enter so next read_line works
        last_activity = time(NULL);

        if (choice == 1) add_entry();
        else if (choice == 2) list_entries(0);
        else if (choice == 3) list_entries(1);
        else if (choice == 4) list_by_category();
        else if (choice == 5) show_categories();
        else if (choice == 6) search_entries();
        else if (choice == 7) delete_entry();
        else if (choice == 8) edit_entry();
        else if (choice == 9) {
            char tmp[32];
            printf("Length? (e.g. 16, 32, 64): ");
            read_line(tmp, sizeof(tmp));
            int len = atoi(tmp);
            if (len < 8) len = 16; if (len > 64) len = 64;
            char gen[MAX_LEN];
            generate_password(gen, len);
            printf(GREEN "Generated: %s\n" RESET, gen);
            password_strength(gen);
            copy_to_clipboard(gen);
        }
        else if (choice == 10) change_master();
        else if (choice == 11) { save_vault(); printf(GREEN "Saved. Bye!\n" RESET); break; }
        else printf(RED "Invalid choice\n" RESET);

        if (choice != 11) {
            printf("\nPress Enter to continue...");
            char dummy[8]; read_line(dummy, sizeof(dummy));
        }
    }
    return 0;
}
