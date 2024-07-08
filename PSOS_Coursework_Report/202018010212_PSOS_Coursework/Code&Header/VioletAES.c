#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/stat.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <sys/time.h>  // For gettimeofday
#include <unistd.h>    // For sleep
// #include <PKCS7.h>
/*This can be excluded since the main code has define the attributes
This is only used for further expandability for the exncryption code
*/
#define MESSAGE_PIECE_LEN   16
#define MAX_FILES 10
// Define a structure for list node
typedef struct ListNode {
    char filename[256];  // Assuming maximum filename length is 255 characters
    unsigned char key[32];
    unsigned char iv[16];
    struct ListNode *next;
} ListNode;

// Define a structure for list
typedef struct {
    ListNode *head;
} List;

typedef struct {
    char inputFilename[256];
    char outputFilename[256];
    char dbFilename[256];
    struct timeval start_time, end_time;
    char operation;
    List* list;
} ThreadData;

typedef struct {
    unsigned char key[32];
    unsigned char iv[16];
    char outputFilename[256];  // to link the encryption key with the file
} KeyIV;

// global list for key and IV storage
KeyIV key_iv_list[MAX_FILES];
int key_iv_count = 0;  // to keep track of the elements within the list


pthread_barrier_t start_barrier;
pthread_mutex_t db_mutex;

//initialize an Linked list to store the information from database(A secured located file)
void init_list(List *list);
//adding information into the linked list
void insert_list_entry(List *list, const char *filename, const unsigned char *key, const unsigned char *iv);
//remove the corresponding files to update the database
void remove_list_entry(List *list, const char *filename);
//free the allocated memory
void free_list(List *list);
//the main part of file processing, including encyrptiona and decryption
void* process_file(void* arg);
//the specific method for encryption
void encrypt_single_file(const char *inputFilename, const char *outputFilename, const char *db_filename);
//the specific method for decryption
int decrypt_single_file(const char *inputFilename, const char *outputFilename, const char *db_filename);
// check if there are ducplicated files with in the output file when decryptin or encryptin
int check_file_duplicate(const char * filename, const char *db_filename);
//update the database
void update_db_file(const char *db_filename, List *list);
//delete specific files
int delete_file(const char *filename);
//Save each unique key and vector of each file
void save_key_iv(const char *db_filename, const char *output_filename, const unsigned char *key, const unsigned char *iv, int key_len, int iv_len);
//load the key store before for decrypting
int load_key_iv(const char *db_filename, const char *filename, unsigned char *key, unsigned char *iv, int key_len, int iv_len);
void print_list(const List *list);

// Function to initialize an empty list
void init_list(List *list) {
    list->head = NULL;
}

// Function to insert a filename, key, and IV into the list
void insert_list_entry(List *list, const char *filename, const unsigned char *key, const unsigned char *iv) {
    ListNode *new_node = (ListNode *)malloc(sizeof(ListNode));
    if (new_node == NULL) {
        fprintf(stderr, "Memory allocation failed.\n");
        exit(EXIT_FAILURE);
    }
    strcpy(new_node->filename, filename);
    memcpy(new_node->key, key, sizeof(new_node->key));
    memcpy(new_node->iv, iv, sizeof(new_node->iv));
    new_node->next = list->head;
    list->head = new_node;
    //  printf("Inserted entry into list: %s\n", filename);  // Debugging output
}

/*Remove the file in the list, for example when decrypting the file, 
*it should remove specific content related to the this file
*/
void remove_list_entry(List *list, const char *filename) {
     printf("Attempting to remove file: %s\n", filename);
    ListNode *current = list->head;
    ListNode *prev = NULL;
    while (current != NULL) {
        if (strcmp(current->filename, filename) == 0) {
            if (prev == NULL) {
                list->head = current->next;
            } else {
                prev->next = current->next;
            }
            free(current);
            return;
        }
        prev = current;
        current = current->next;
    }
    printf("File not found in list: %s\n", filename);
}

// Function to free the memory occupied by the list
void free_list(List *list) {
    ListNode *current = list->head;
    while (current != NULL) {
        ListNode *temp = current;
        current = current->next;
        free(temp);
    }
    list->head = NULL;
}


/*
Function to convert binary data to hex string
this sets the base for encrypting and decrypting other types od files
Video, images etc
*/ 
char *bin2hex(const unsigned char *bin, int len) {
    char *hex = malloc(len * 2 + 1);
    for (int i = 0; i < len; i++) {
        sprintf(hex + i * 2, "%02X", bin[i]);
    }
    hex[len * 2] = '\0';
    return hex;
}

// Function to convert hex string to binary data
void hex2bin(const char *hex, unsigned char *bin, int len) {
    for (int i = 0; i < len; i++) {
        sscanf(hex + i * 2, "%02hhX", &bin[i]);
    }
}

/*
Generate random AES key and IV
Randomly generates the AES encryption 
key and Initial vector based on the library of openssl
*/ 
int generate_key_and_iv(unsigned char *key, unsigned char *iv, int key_size, int iv_size) {
    if (!RAND_bytes(key, key_size)) {// using random bytes to encrypt 
        fprintf(stderr, "Error generating random key.\n");
        return 0;
    }
    if (!RAND_bytes(iv, iv_size)) {//if 
        fprintf(stderr, "Error generating random IV.\n");
        return 0;
    }
    return 1;
}


/*Saving the key to the database file called (key_iv_db.ent)*/
void save_key_iv(const char *db_filename, const char *output_filename, const unsigned char *key, const unsigned char *iv, int key_len, int iv_len) {
    char *hex_key = bin2hex(key, key_len);
    char *hex_iv = bin2hex(iv, iv_len);

    pthread_mutex_lock(&db_mutex); // protect the file using mutex
    FILE *db_file = fopen(db_filename, "a");
    if (db_file) {
        fprintf(db_file, "%s,%s,%s\n", output_filename, hex_key, hex_iv);
        fclose(db_file);
    } else {
        fprintf(stderr, "Failed to open database file for writing.\n");
    }
    pthread_mutex_unlock(&db_mutex); // unlock the mutex

    free(hex_key);
    free(hex_iv);
}



// Load key and IV from a database file
int load_key_iv(const char *db_filename, const char *filename, unsigned char *key, unsigned char *iv, int key_len, int iv_len) {
    FILE *db_file = fopen(db_filename, "r");
    if (!db_file) {
        fprintf(stderr, "Failed to open database file for reading.\n");
        return 0;
    }
    char line[256];
    while (fgets(line, sizeof(line), db_file)) {
        //this here helps loading the correct structure of data in database file
        char *saved_filename = strtok(line, ",");
        char *saved_key = strtok(NULL, ",");
        char *saved_iv = strtok(NULL, ",");
        if (strcmp(saved_filename, filename) == 0) {
            hex2bin(saved_key, key, key_len);
            hex2bin(saved_iv, iv, iv_len);
            fclose(db_file);
            return 1;
        }
    }
    fclose(db_file);
    return 0;
}



/*reading the file (Notice, 
*this is reading the file thats about to be encrypt or decrypt)
*/
unsigned char *read_file(const char *filename, int *length) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Failed to open file for reading");
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    *length = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char *data = malloc(*length);
    if (data) {
        fread(data, 1, *length, file);
    }
    fclose(file);
    return data;
}


/*Function to read data from the database file and build the list
read the database file only
*/
// void read_db_file(const char *db_filename, List *list) {
//     FILE *file = fopen(db_filename, "r");
//     if (!file) {
//         fprintf(stderr, "Failed to open file: %s\n", db_filename);
//         return;
//     }
//     char line[256];
//     while (fgets(line, sizeof(line), file)) {
//         char *filename = strtok(line, ",");
//         char *hex_key = strtok(NULL, ",");
//         char *hex_iv = strtok(NULL, ",");
//         unsigned char key[32], iv[16];
//         hex2bin(hex_key, key, sizeof(key));
//         hex2bin(hex_iv, iv, sizeof(iv));
//         insert_list_entry(list, filename, key, iv);
//     }
//     fclose(file);
// }

void read_db_file(const char *db_filename, List *list) {
    FILE *file = fopen(db_filename, "r");
    if (!file) {
        fprintf(stderr, "Failed to open file: %s\n", db_filename);
        return;
    }
    char line[256];
    while (fgets(line, sizeof(line), file)) {
        char *filename = strtok(line, ",");
        char *hex_key = strtok(NULL, ",");
        char *hex_iv = strtok(NULL, ",");
        if (filename && hex_key && hex_iv) {
            unsigned char key[32], iv[16];
            hex2bin(hex_key, key, sizeof(key));
            hex2bin(hex_iv, iv, sizeof(iv));
            insert_list_entry(list, filename, key, iv);
            // printf("Inserted file: %s\n", filename);  // Debugging output
        } else {
            printf("Failed to parse line: %s\n", line);  // Debugging output
        }
    }
    fclose(file);
}


// Function to update the database file after decryption
void update_db_file(const char *db_filename, List *list) {
    // Open file in write mode to overwrite
    FILE *db_file = fopen(db_filename, "w"); 
    if (!db_file) {
        fprintf(stderr, "Failed to open database file for writing.\n");
        return;
    }
    ListNode *current = list->head;
    while (current != NULL) {
        char *hex_key = bin2hex(current->key, sizeof(current->key));
        char *hex_iv = bin2hex(current->iv, sizeof(current->iv));
        fprintf(db_file, "%s,%s,%s\n", current->filename, hex_key, hex_iv);
        free(hex_key);
        free(hex_iv);
        current = current->next;
    }
    fclose(db_file);
     printf("Database file %s updated.\n", db_filename);
}


//Write the content into the desired file, 
//such as encrypted----> decrypt / decrypt--->encrypt
void write_file(const char *filename, 
const unsigned char *data, int length) {
    FILE *file = fopen(filename, "wb");
    if (!file) {
        perror("Failed to open file for writing");
        return;
    }
    fwrite(data, 1, length, file);
    fclose(file);
}

//check whether whether the input file exists
int check_file_exists(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (file) {
        fclose(file);
        return 1; // file exist
    }
    return 0; // file does not exist
}

//chekcing the duplication
int check_file_duplicate(const char * filename, const char *db_filename){
    FILE *file = fopen(db_filename, "r");
    if (!file) {
        fprintf(stderr, "Failed to open database file.\n");
        return 0;
    }

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        // each line contains filename, encryption key, initial vector
        char *comma = strchr(line, ',');
        if (comma) {
            *comma = '\0';  // cut the string, only the file name remains
        }
        if (strcmp(line, filename) == 0) {
            fclose(file);
            return 1;  // duplicate found
        }
    }

    fclose(file);
    return 0; 
}

//delete the source file after encryptin / decrypting
int delete_file(const char *filename){
    if(remove(filename) == 0){
        return 1;
    
    }else {
        perror("Failed to delete file");
        return 0;
    }
}


// Give the input proper padding
unsigned int PKCS7Padding(char *p, unsigned int plen)
{
    unsigned int padding_len = 0;
    unsigned char padding_value = 0;

    if(0 < plen){
        if(0 ==(plen % MESSAGE_PIECE_LEN)){
            padding_value = MESSAGE_PIECE_LEN;
        }
        else{
            padding_value = MESSAGE_PIECE_LEN - (plen % MESSAGE_PIECE_LEN);
        }

        padding_len = (plen / MESSAGE_PIECE_LEN + 1) * MESSAGE_PIECE_LEN;

        for( ; plen < padding_len; plen++){
            p[plen] = padding_value;
        }
    }
    return padding_len;
}


unsigned int PKCS7Cutting(char *p, unsigned int plen, unsigned int max_len) {
    if (plen == 0 || plen > max_len) {
        return 0;
    }

    unsigned char lastByte = p[plen - 1];
    if (lastByte > MESSAGE_PIECE_LEN || lastByte == 0 || lastByte > plen) {
        return 0;
    }

    unsigned int padding_len = lastByte;

    for (unsigned int i = 0; i < padding_len; i++) {
        if (p[plen - 1 - i] != lastByte) {
            return 0;
        }
    }
    return plen - padding_len;
}


// store the global key and iv
void store_key_iv(const char *outputFilename, const unsigned char *key, const unsigned char *iv) {
    if (key_iv_count >= MAX_FILES) {
        fprintf(stderr, "Reached maximum key/IV storage capacity.\n");
        return;
    }

    KeyIV *entry = &key_iv_list[key_iv_count++];
    memcpy(entry->key, key, sizeof(entry->key));
    memcpy(entry->iv, iv, sizeof(entry->iv));
    strncpy(entry->outputFilename, outputFilename, sizeof(entry->outputFilename) - 1);
}


//encrypting the file with specific procedure 
void encrypt_single_file(const char *inputFilename, const char *outputFilename, const char *db_filename) {
    unsigned char key[32], iv[16];
    AES_KEY aes_key;

    // check the existance of file
    if (!check_file_exists(inputFilename)) {
        fprintf(stderr, "Input file does not exist. Please check the file name and try again.\n");
        return;
    }
    
    // key and IV generation
    if (!generate_key_and_iv(key, iv, sizeof(key), sizeof(iv))
     || AES_set_encrypt_key(key, 256, &aes_key) < 0) {
        fprintf(stderr, "Failed to set encryption key.\n");
        return;
    }
    save_key_iv(db_filename, outputFilename, key, iv, sizeof(key), sizeof(iv));

    // read the file
    FILE *file = fopen(inputFilename, "rb");
    if (!file) {
        perror("Failed to open file for reading");
        return;
    }

    fseek(file, 0, SEEK_END);
    int data_len = ftell(file);
    rewind(file);

    // allocates the memory for AES block
    int size = data_len + AES_BLOCK_SIZE;
    unsigned char *file_data = (unsigned char *)malloc(size);

    if (!file_data) {
        fprintf(stderr, "Failed to allocate memory for file data.\n");
        fclose(file);
        return;
    }

    // read the file into the allocated memory
    fread(file_data, 1, data_len, file);
    fclose(file);

    // Padding for input data
    unsigned int padded_data_len = PKCS7Padding((char*)file_data, data_len);
    if (padded_data_len == 0) {
        fprintf(stderr, "Padding failed.\n");
        free(file_data);
        return;
    }

    // the length after encryption is based on the padding
    int out_len = ((padded_data_len + AES_BLOCK_SIZE - 1) 
    / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    unsigned char *out_data = (unsigned char*)malloc(out_len);
    if (!out_data) {
        fprintf(stderr, "Failed to allocate memory for encrypted data.\n");
        free(file_data);
        return;
    }

    // AES encryptin method, called from the library
    AES_cbc_encrypt(file_data, out_data, padded_data_len, &aes_key, iv, AES_ENCRYPT);
    write_file(outputFilename, out_data, out_len);

    // release the memory
    free(file_data);
    free(out_data);
    printf("Encryption completed. Output file is %s\n", outputFilename);
}



int decrypt_single_file(const char *inputFilename, const char *outputFilename, const char *db_filename) {
    unsigned char key[32], iv[16];
    AES_KEY aes_key;

    if (!check_file_exists(inputFilename)) {
        fprintf(stderr, "Input file does not exist for decryption. Please check the file name and try again.\n");
        return 0;
    }

    if (!load_key_iv(db_filename, inputFilename, key, iv, sizeof(key), sizeof(iv)) || AES_set_decrypt_key(key, 256, &aes_key) < 0) {
        fprintf(stderr, "Failed to set decryption key or no key/IV pair found.\n");
        return 0;
    }

    int data_len;
    unsigned char *encrypted_data = read_file(inputFilename, &data_len);
    if (!encrypted_data) return 0;

    int out_len = data_len;
    unsigned char *decrypted_data = malloc(out_len);
    if (!decrypted_data) {
        free(encrypted_data);
        return 0;
    }

    AES_cbc_encrypt(encrypted_data, decrypted_data, data_len, &aes_key, iv, AES_DECRYPT);

    unsigned int actual_data_len = PKCS7Cutting((char*)decrypted_data, out_len, out_len);
    if (actual_data_len == 0) {
        fprintf(stderr, "Failed to remove PKCS7 padding.\n");
        free(encrypted_data);
        free(decrypted_data);
        return 0;
    }

    write_file(outputFilename, decrypted_data, actual_data_len);

    free(encrypted_data);
    free(decrypted_data);
    printf("Decryption completed. Output file is %s\n", outputFilename);
    return 1; // indicate success
}





//this here allows for removing the extra characters of the input file path (such as " ' ")
void remove_apostrophes(char *str) {
    char *p = str; 
    char *q = str; 

    while (*p) {
        if (*p != '\'') { 
            *q++ = *p;
        }
        p++;
    }
    *q = '\0'; 
}

//processing the file with multi-thread
void* process_file(void* arg) {//with in this, it contains operation of multi thread
    ThreadData* data = (ThreadData*)arg;

    pthread_barrier_wait(&start_barrier);// starting the barrier
    gettimeofday(&data->start_time, NULL);
     // print the start time of the thread
    printf("Thread processing %s started at %ld seconds and %ld microseconds.\n", data->inputFilename, data->start_time.tv_sec, data->start_time.tv_usec);


    pthread_mutex_lock(&db_mutex);//the process is protected by mutex lock
    int is_duplicate = check_file_duplicate(data->outputFilename, data->dbFilename);
    pthread_mutex_unlock(&db_mutex);

    if (is_duplicate) {
        fprintf(stderr, "Output filename %s already exists in the database. Please choose a different name.\n", data->outputFilename);
        return NULL;
    }
    int success = 0; 
    if (data->operation == 'e') {//encryption based on the command of user
        encrypt_single_file(data->inputFilename, data->outputFilename, data->dbFilename);
        success = 1;
    } else if (data->operation == 'd') {//decryption based on the command of user
        success = decrypt_single_file(data->inputFilename, data->outputFilename, data->dbFilename);
    }

    // Attempt to delete the input file after encryption/decryption
    if (!success) { 
        fprintf(stderr, "Failed to process the file: %s.\n", data->inputFilename);
    } else {
        if (!delete_file(data->inputFilename)) {
            fprintf(stderr, "Failed to delete the file %s.\n", data->inputFilename);
        }
    }

    gettimeofday(&data->end_time, NULL);
    printf("Thread processing %s ended.\n", data->inputFilename);
    return (void*)(intptr_t)success; 
}



void print_list(const List *list) {
    ListNode *current = list->head;
    printf("List Contents:\n");
    while (current != NULL) {
        printf("Filename: %s\n", current->filename);
        current = current->next;
    }
}


int main() {// the main logic of the program
    pthread_t threads[MAX_FILES];
    ThreadData data[MAX_FILES];
    // the location of the database file
    char dbFilename[] = "/mnt/hgfs/SFS/TestingCode/key_iv_db.ent";
    // char dbFilename[] = "/var/lib/EncryptionDB/key_iv_db.ent";
    char option;
    int fileCount = 0;
    // Initialize the list for each option selection

    List list;
    // init_list(&list);
    // read_db_file(dbFilename, &list); // Read database file once

    pthread_mutex_init(&db_mutex, NULL);// Start the mutex
    // initialize the barrier as the mas file number
    pthread_barrier_init(&start_barrier, NULL, MAX_FILES); 

    struct timeval program_start, program_end;
    gettimeofday(&program_start, NULL);

    while (1) {

        init_list(&list);
        read_db_file(dbFilename, &list);

        // printf("List after reading database file:\n");
        // print_list(&list);

        char optionInput[10];  // Reasonable length for user input
        option = 0;
        printf("Do you want to (E)ncrypt, (D)ecrypt, or (Q)uit? Enter 'E', 'D', or 'Q': ");
        fgets(optionInput, sizeof(optionInput), stdin);
        if (strchr(optionInput, '\n') == NULL) {
            while (getchar() != '\n');  // clear the buffer
        }
        for (int i = 0; optionInput[i]; i++) {
            optionInput[i] = tolower(optionInput[i]);
        }
        if (strcmp(optionInput, "e\n") == 0) {
            option = 'e';
        } else if (strcmp(optionInput, "d\n") == 0) {
            option = 'd';
        } else if (strcmp(optionInput, "q\n") == 0) {
            option = 'q';
        } else {
            printf("Invalid option. Please enter 'E', 'D', or 'Q'.\n");
            continue;
        }

        if (option == 'q') {
            printf("Exiting program.\n");
            break;
        }

        printf("Enter the file paths to encrypt/decrypt, separated by spaces: ");
        char buffer[1024];
        fgets(buffer, sizeof(buffer), stdin);
        
        buffer[strcspn(buffer, "\n")] = 0; // Remove newline
        remove_apostrophes(buffer);
        char *token = strtok(buffer, " ");
        fileCount = 0;

        while (token && fileCount < MAX_FILES) {
            strcpy(data[fileCount].inputFilename, token);
            strcpy(data[fileCount].outputFilename, token);
            strcpy(data[fileCount].dbFilename, dbFilename);
            char *dot = strrchr(data[fileCount].outputFilename, '.');
            if (option == 'e') {
                if (dot) {
                    strcpy(dot, ".en");  // Change extension for encryption
                    data[fileCount].operation = 'e';
                } else {
                    fprintf(stderr, "Error: File does not have an extension. Please enter a valid file with extension.\n");
                    break; // Skip this file and continue with the next token
                }
            } else if (option == 'd') {       
                if (dot && strcmp(dot, ".en") == 0) {
                    //removing the specific head file in the database
                    remove_list_entry(&list, data[fileCount].inputFilename);
                    strcpy(dot, ".txt");  // Change extension for decryption
                    data[fileCount].operation = 'd';
                } else {
                    fprintf(stderr, "Error: File for decryption does not have the expected .en extension.\n");
                    break; // Skip this file and continue with the next token
                }
            }
            fileCount++;
            token = strtok(NULL, " ");
        }
        // Initialize barrier with the actual number of files + 1 for main thread
        pthread_barrier_destroy(&start_barrier);
        pthread_barrier_init(&start_barrier, NULL, fileCount + 1);

        for (int i = 0; i < fileCount; i++) {
            pthread_create(&threads[i], NULL, process_file, &data[i]);
        }
        //wait for each thread to be over
        pthread_barrier_wait(&start_barrier);

        for (int i = 0; i < fileCount; i++) {
            void* status;
            //multi-thread stops and joined together
            pthread_join(threads[i], NULL);
             // return the void pointer and interpret the status of decryption
            int success = (int)(intptr_t)status; 
            
            long microseconds = (data[i].end_time.tv_sec - data[i].start_time.tv_sec) * 1000000L + (data[i].end_time.tv_usec - data[i].start_time.tv_usec);
            printf("Thread processing %s ran for %ld microseconds.\n", data[i].inputFilename, microseconds);
            
            // check the success of decryption
            if (data[i].operation == 'd' && success) {
                pthread_mutex_lock(&db_mutex);
                
                printf("Before removing entry:\n");
                print_list(&list);  // P
                remove_list_entry(&list, data[i].inputFilename);
                printf("After removing entry:\n");
                print_list(&list);  // Print the list after removing the entr
                pthread_mutex_unlock(&db_mutex);
            }
        }
        pthread_barrier_destroy(&start_barrier);
        pthread_mutex_destroy(&db_mutex);
        if (option == 'd') {
            // printf("This is the lit \n\n");
            // print_list(&list);
            // printf("Above is the lit \n\n");
            update_db_file(dbFilename, &list); // Update database after all decryption threads are complete
        }
        // Free the list after processing all files for this option
    }
    gettimeofday(&program_end, NULL);
    long total_program_time = (program_end.tv_sec - program_start.tv_sec) * 1000000L + (program_end.tv_usec - program_start.tv_usec);
    printf("Total program run time: %ld microseconds\n", total_program_time);
    free_list(&list);
    pthread_mutex_destroy(&db_mutex);
    return 0;
}


