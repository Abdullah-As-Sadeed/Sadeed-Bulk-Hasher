/* By Abdullah As-Sadeed */

/*
gcc ./Sadeed_Bulk_Hasher.cpp -o ./Sadeed_Bulk_Hasher -lssl -lcrypto
*/

#include "csignal"
#include "iostream"
#include "stdio.h"
#include "string.h"
#include "dirent.h"
#include "openssl/evp.h"

#define TERMINAL_TITLE_START "\033]0;"
#define TERMINAL_TITLE_END "\007"

#define TERMINAL_ANSI_COLOR_RED "\x1b[31m"
#define TERMINAL_ANSI_COLOR_GREEN "\x1b[32m"
#define TERMINAL_ANSI_COLOR_YELLOW "\x1b[33m"
#define TERMINAL_ANSI_COLOR_RESET "\x1b[0m"

#define STORAGE_FILE "Hash_Values.txt"

void Calculate_Hash(const char *file_path, const EVP_MD *hash_function, unsigned char *hash_value, const char *hash_name)
{
    printf("Calculating %s hash for file: %s\n", hash_name, file_path);

    FILE *file = fopen(file_path, "rb");
    if (file == NULL)
    {
        fprintf(stderr, TERMINAL_ANSI_COLOR_RED "Error opening file: %s\n" TERMINAL_ANSI_COLOR_RESET, file_path);
        return;
    }

    EVP_MD_CTX *context = EVP_MD_CTX_new();
    if (context == NULL)
    {
        fprintf(stderr, TERMINAL_ANSI_COLOR_RED "Error creating hash context for %s.\n" TERMINAL_ANSI_COLOR_RESET, hash_name);
        fclose(file);
        return;
    }

    if (EVP_DigestInit_ex(context, hash_function, NULL) != 1)
    {
        fprintf(stderr, TERMINAL_ANSI_COLOR_RED "Error initializing hash function %s.\n" TERMINAL_ANSI_COLOR_RESET, hash_name);
        EVP_MD_CTX_free(context);
        fclose(file);
        return;
    }

    unsigned char buffer[1024];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) != 0)
    {
        if (EVP_DigestUpdate(context, buffer, bytes_read) != 1)
        {
            fprintf(stderr, TERMINAL_ANSI_COLOR_RED "Error updating hash function %s.\n" TERMINAL_ANSI_COLOR_RESET, hash_name);
            EVP_MD_CTX_free(context);
            fclose(file);
            return;
        }
    }

    unsigned int hash_length;
    if (EVP_DigestFinal_ex(context, hash_value, &hash_length) != 1)
    {
        fprintf(stderr, TERMINAL_ANSI_COLOR_RED "Error finalizing hash function %s.\n" TERMINAL_ANSI_COLOR_RESET, hash_name);
        EVP_MD_CTX_free(context);
        fclose(file);
        return;
    }

    EVP_MD_CTX_free(context);
    fclose(file);
}

void List_Files_and_Calculate_Hash(const char *directory_path, FILE *output_file)
{
    DIR *directory = opendir(directory_path);
    if (directory == NULL)
    {
        fprintf(stderr, TERMINAL_ANSI_COLOR_RED "Error opening directory: %s\n" TERMINAL_ANSI_COLOR_RESET, directory_path);
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL)
    {
        if (entry->d_type == DT_DIR)
        {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            {
                continue;
            }

            char sub_directory_path[1024];
            snprintf(sub_directory_path, sizeof(sub_directory_path), "%s/%s", directory_path, entry->d_name);

            List_Files_and_Calculate_Hash(sub_directory_path, output_file);
        }
        else if (entry->d_type == DT_REG)
        {
            char file_path[1024];
            snprintf(file_path, sizeof(file_path), "%s/%s", directory_path, entry->d_name);

            EVP_MD_CTX *context = EVP_MD_CTX_new();
            if (context == NULL)
            {
                fprintf(stderr, TERMINAL_ANSI_COLOR_RED "Error creating hash context.\n" TERMINAL_ANSI_COLOR_RESET);
                continue;
            }

            unsigned char md5_hash[EVP_MAX_MD_SIZE];
            Calculate_Hash(file_path, EVP_md5(), md5_hash, "MD5");

            unsigned char sha1_hash[EVP_MAX_MD_SIZE];
            Calculate_Hash(file_path, EVP_sha1(), sha1_hash, "SHA1");

            unsigned char sha224_hash[EVP_MAX_MD_SIZE];
            Calculate_Hash(file_path, EVP_sha224(), sha224_hash, "SHA224");

            unsigned char sha256_hash[EVP_MAX_MD_SIZE];
            Calculate_Hash(file_path, EVP_sha256(), sha256_hash, "SHA256");

            unsigned char sha384_hash[EVP_MAX_MD_SIZE];
            Calculate_Hash(file_path, EVP_sha384(), sha384_hash, "SHA384");

            unsigned char sha512_hash[EVP_MAX_MD_SIZE];
            Calculate_Hash(file_path, EVP_sha512(), sha512_hash, "SHA512");

            unsigned char sha3_hash[EVP_MAX_MD_SIZE];
            Calculate_Hash(file_path, EVP_sha3_256(), sha3_hash, "SHA3");

            printf("\n");

            fprintf(output_file, "File: %s\n", file_path);

            fprintf(output_file, "MD5: ");
            for (int i = 0; i < EVP_MD_size(EVP_md5()); i++)
            {
                fprintf(output_file, "%02x", md5_hash[i]);
            }
            fprintf(output_file, "\n");

            fprintf(output_file, "SHA1: ");
            for (int i = 0; i < EVP_MD_size(EVP_sha1()); i++)
            {
                fprintf(output_file, "%02x", sha1_hash[i]);
            }
            fprintf(output_file, "\n");

            fprintf(output_file, "SHA224: ");
            for (int i = 0; i < EVP_MD_size(EVP_sha224()); i++)
            {
                fprintf(output_file, "%02x", sha224_hash[i]);
            }
            fprintf(output_file, "\n");

            fprintf(output_file, "SHA256: ");
            for (int i = 0; i < EVP_MD_size(EVP_sha256()); i++)
            {
                fprintf(output_file, "%02x", sha256_hash[i]);
            }
            fprintf(output_file, "\n");

            fprintf(output_file, "SHA384: ");
            for (int i = 0; i < EVP_MD_size(EVP_sha384()); i++)
            {
                fprintf(output_file, "%02x", sha384_hash[i]);
            }
            fprintf(output_file, "\n");

            fprintf(output_file, "SHA512: ");
            for (int i = 0; i < EVP_MD_size(EVP_sha512()); i++)
            {
                fprintf(output_file, "%02x", sha512_hash[i]);
            }
            fprintf(output_file, "\n");

            fprintf(output_file, "SHA3: ");
            for (int i = 0; i < EVP_MD_size(EVP_sha3_256()); i++)
            {
                fprintf(output_file, "%02x", sha3_hash[i]);
            }
            fprintf(output_file, "\n\n");
        }
    }

    closedir(directory);
}

void Handle_Signal(int signal)
{
    if (signal == SIGINT)
    {
        printf(TERMINAL_ANSI_COLOR_RED "\n\nYou interrupted me by SIGINT signal.\n" TERMINAL_ANSI_COLOR_RESET);
        exit(signal);
    }
}

int main(int argument_count, char *argument_values[])
{
    signal(SIGINT, Handle_Signal);

    printf(TERMINAL_TITLE_START "Sadeed Bulk Hasher" TERMINAL_TITLE_END);

    if (argument_count != 2)
    {
        fprintf(stderr, TERMINAL_ANSI_COLOR_YELLOW "Usage: %s <directory_path>\n" TERMINAL_ANSI_COLOR_RESET, argument_values[0]);
        return 1;
    }

    const char *directory_path = argument_values[1];

    printf(TERMINAL_TITLE_START "Sadeed Bulk Hasher: working for %s" TERMINAL_TITLE_END, directory_path);

    FILE *output_file = fopen(STORAGE_FILE, "r");
    if (output_file != NULL)
    {
        fclose(output_file);

        printf(TERMINAL_ANSI_COLOR_YELLOW "'%s' file already exists. Do you want to overwrite it? (y/n): " TERMINAL_ANSI_COLOR_RESET, STORAGE_FILE);
        char response;
        scanf(" %c", &response);

        if (response != 'y' && response != 'Y')
        {
            printf(TERMINAL_ANSI_COLOR_RED "Operation cancelled. Existing file was not overwritten.\n" TERMINAL_ANSI_COLOR_RESET);
            return 0;
        }
    }

    output_file = fopen(STORAGE_FILE, "w");
    if (output_file == NULL)
    {
        fprintf(stderr, TERMINAL_ANSI_COLOR_RED "Error creating output file.\n" TERMINAL_ANSI_COLOR_RESET);
        return 1;
    }

    OpenSSL_add_all_digests();

    List_Files_and_Calculate_Hash(directory_path, output_file);

    EVP_cleanup();
    fclose(output_file);

    printf(TERMINAL_ANSI_COLOR_GREEN "Hash values saved in '%s'\n" TERMINAL_ANSI_COLOR_RESET, STORAGE_FILE);

    return 0;
}
