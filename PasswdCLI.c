#ifdef _WIN32 
#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <io.h>
#include <AclAPI.h>
#include <sddl.h>
#include <sys/stat.h>
#define access _access
#define F_OK 0
/*#define chmod _chmod*/
#define PERM_WRITE S_IWRITE
#define PERM_READ S_IREAD
void set_win_perm(const char* filename) {
    // Converts the name of the file in wide string.
    wchar_t wfilename[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, filename, -1, wfilename, MAX_PATH);

    // Get current user's SID (owner).
    HANDLE hToken;
    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);

    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
    TOKEN_USER* pTokenUser = (TOKEN_USER*)malloc(dwSize);
    GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize);

    // SID of Administrators.
    PSID pAdminSID = NULL;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    AllocateAndInitializeSid(&NtAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &pAdminSID);

    // Creates 2 ACE: one for owner, one for admins.
    EXPLICIT_ACCESSW ea[2] = { 0 };

    // Owner: complete control.
    ea[0].grfAccessPermissions = GENERIC_ALL;
    ea[0].grfAccessMode = SET_ACCESS;
    ea[0].grfInheritance = NO_INHERITANCE;
    ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[0].Trustee.TrusteeType = TRUSTEE_IS_USER;
    ea[0].Trustee.ptstrName = (LPWSTR)pTokenUser->User.Sid;

    // Admins: complete control.
    ea[1].grfAccessPermissions = GENERIC_ALL;
    ea[1].grfAccessMode = SET_ACCESS;
    ea[1].grfInheritance = NO_INHERITANCE;
    ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[1].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[1].Trustee.ptstrName = (LPWSTR)pAdminSID;

    // Creates the DACL.
    PACL pACL = NULL;
    SetEntriesInAclW(2, ea, NULL, &pACL);


    // Creates the security descriptor and applies it to the file.
    PSECURITY_DESCRIPTOR pSD = (PSECURITY_DESCRIPTOR)
        LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
    if (!pSD) {
        LocalFree(pACL);
        FreeSid(pAdminSID);
        free(pTokenUser);
        CloseHandle(hToken);
        return;
    }
    if (SetEntriesInAclW(2, ea, NULL, &pACL) != ERROR_SUCCESS || !pACL) {
        LocalFree(pSD);
        FreeSid(pAdminSID);
        free(pTokenUser);
        CloseHandle(hToken);
        return;
    }
    if (!pTokenUser) {
        FreeSid(pAdminSID);
        CloseHandle(hToken);
        return;
    }
    InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(pSD, TRUE, pACL, FALSE);
    SetFileSecurityW(wfilename, DACL_SECURITY_INFORMATION, pSD);

    // Clear.
    LocalFree(pACL);
    LocalFree(pSD);
    FreeSid(pAdminSID);
    free(pTokenUser);
    CloseHandle(hToken);
}
void set_readonly(const char* filename) {
    set_win_perm(filename);
    DWORD attrs = GetFileAttributesA(filename);
    if (attrs != INVALID_FILE_ATTRIBUTES)
        SetFileAttributesA(filename, attrs | FILE_ATTRIBUTE_READONLY);
}

void set_writable(const char* filename) {
    DWORD attrs = GetFileAttributesA(filename);
    if (attrs != INVALID_FILE_ATTRIBUTES)
        SetFileAttributesA(filename, attrs & ~FILE_ATTRIBUTE_READONLY);
}
#else 
#include <unistd.h>
#include <sys/stat.h>
#define PERM_WRITE 0700
#define PERM_READ 0444
void set_readonly(const char* filename) {
    chmod(filename, PERM_READ);
}

void set_writable(const char* filename) {
    chmod(filename, PERM_WRITE);
}
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sodium.h>
#include <locale.h>

#define MAX_SERVICES 10000
#define SIZE_NAME 500
#define SIZE_PASSWD SIZE_NAME
#define FILE_PASSWD "password.dat" 
#define FILE_MASTER "master.dat"
#define MASTER_PASS_LEN 256 // Define buffer dimension to get the input of master password.
#define HASH_LEN 32 // Defines the size of the hash in 32 byte (256 bit).
#define ENCRYPTED_BUFFER ((SIZE_PASSWD + crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES) * 2 + 1) // Defines the size of the buffer that contains the HEX string.
unsigned char key[crypto_secretbox_KEYBYTES];

// WARNING: TO WORK PROPERLY THE PROGRAM REQUIRES THE FILES master.dat AND password.dat IN THE SAME WORKING DIRECTORY (OTHERWISE NEW ONES WILL BE CREATED).
// THE FILES password.dat AND master.dat MUSTN'T BE MODIFIED WITHOUT THIS PROGRAM (ANY EXTERNAL CHANGE WILL CAUSE PASSWORDS LOST).

// Function to encrypt using libsodium.
void encrypt_text(const char *input, char *output) {
  unsigned char nonce[crypto_secretbox_NONCEBYTES];
  randombytes_buf(nonce, sizeof nonce); // Nonce is casual.

  unsigned char ciphertext[SIZE_PASSWD + crypto_secretbox_MACBYTES];
  size_t len = strlen(input);

  crypto_secretbox_easy(ciphertext, (unsigned char *)input, len, nonce, key);

  int pos = 0;

  for (unsigned int i = 0; i < crypto_secretbox_NONCEBYTES; i++) {
    pos += sprintf(output + pos, "%02x", nonce[i]);
  }

  for (unsigned int i = 0; i < len + crypto_secretbox_MACBYTES; i++) {
    pos += sprintf(output + pos, "%02x", ciphertext[i]);
  }
}

// Function to decrypt using libsodium.
void decrypt_text(char *str) {
  size_t hex_len = strlen(str);
  unsigned char nonce[crypto_secretbox_NONCEBYTES];
  unsigned char ciphertext[SIZE_PASSWD + crypto_secretbox_MACBYTES + crypto_secretbox_NONCEBYTES];
  int pos = 0;

  for (unsigned int i = 0; i < crypto_secretbox_NONCEBYTES; i++) {
    (void)sscanf(str + pos, "%2hhx", &nonce[i]);
    pos += 2;
  }

  int cipher_len = (int)((hex_len / 2) - crypto_secretbox_NONCEBYTES);
  
  if (cipher_len < (int)crypto_secretbox_MACBYTES) {
	  strcpy(str, "ERROR_DECRYPT");
	  return;
  }
  
  for (int i = 0; i < cipher_len; i++) {
    (void)sscanf(str + pos, "%2hhx", &ciphertext[i]);
    pos += 2;
  }

  unsigned char decrypted[SIZE_PASSWD + crypto_secretbox_MACBYTES];
  
  if (crypto_secretbox_open_easy(decrypted, ciphertext, cipher_len, nonce, key) != 0) {
    strcpy(str, "ERROR_DECRYPT");
    return;
  }

  int plain_len = cipher_len - crypto_secretbox_MACBYTES;
  decrypted[plain_len] = '\0';
  strcpy(str, (char *)decrypted);
}

// Function to remove the newline.
void remove_newline(char *str) {
  str[strcspn(str, "\n")] = 0;
}

// Function to get a valid number.
int get_valid_number(int min, int max) {
  char input[20];

  while (1) {
    printf("\nType a number between %d e %d: ", min, max);
    if (!fgets(input, sizeof(input), stdin)) input[0] = '\0';

    char *endptr;
    long input_number = strtol(input, &endptr, 10);

    // Endptr points to the first non-number character. If \n or \0 input is valid.
    if (endptr != input && (*endptr == '\n' || *endptr == '\0')) {
      if (input_number >= min && input_number <= max) {
	return (int)input_number;
      }
    }
    printf("Error: Type a valid input!\n");
  }
}

// Function to add a service reading keyboard inputs.
void add_service(char service[][SIZE_NAME], char names[][SIZE_NAME], char pass[][SIZE_PASSWD], int *numcont) {
  if (*numcont >= MAX_SERVICES) {
    printf("The database is full.\n");
    return;
  }

  printf("\nType the service (max %i characters): ", SIZE_NAME - 1);
  if (!fgets(service[*numcont], SIZE_NAME, stdin)) service[*numcont][0] = '\0';
  remove_newline(service[*numcont]);
  service[*numcont][SIZE_NAME - 1] = '\0';

  printf("Type the username (max %i characters): ", SIZE_NAME -1);
  if (!fgets(names[*numcont], SIZE_NAME, stdin)) names[*numcont][0] = '\0';
  remove_newline(names[*numcont]);
  names[*numcont][SIZE_NAME - 1] = '\0';

  printf("Type the password (max %i characters): ", SIZE_PASSWD -1);
  if (!fgets(pass[*numcont], SIZE_PASSWD, stdin)) pass[*numcont][0] = '\0';
  remove_newline(pass[*numcont]);
  pass[*numcont][SIZE_PASSWD - 1] = '\0';

  (*numcont)++;
  printf("Service successfully added.\n");
}

// Function to read services (saved in password.dat).
void view_service(char service[][SIZE_NAME], char names[][SIZE_NAME], char pass[][SIZE_PASSWD], int numcont) {
  if (numcont == 0) {
    printf("No services found.\n");
    return;
  }

  for (int i = 0; i < numcont; i++) {
    printf("\nService: %s | Username: %s | Password: %s\n", service[i], names[i], pass[i]);
  }
}

// Function to find saved services.
void find_service(char service[][SIZE_NAME], char names[][SIZE_NAME], char pass[][SIZE_PASSWD], int numcont) {
  char searched_service[SIZE_NAME];
  
  printf("\nType the name of the service you want to find: ");
  if (!fgets(searched_service, SIZE_NAME, stdin)) searched_service[0] = '\0';
  remove_newline(searched_service);

  for (int i = 0; i < numcont; i++) {
    if (strcmp(service[i], searched_service) == 0) {
      printf("\nService found! Username: %s | Password: %s\n", names[i], pass[i]);
    }
  }
  printf("\n------------------------------------------------------\n"); // Print a row if it finds nothing.
}

// Function to delete a service (requires a valid number got with get_valid_number).
void delete_service(char service[][SIZE_NAME], char names[][SIZE_NAME], char pass[][SIZE_PASSWD], int *numcont) {
  char service_to_delete[SIZE_NAME];
  printf("\nType the name of the service you want to delete: ");
  if (!fgets(service_to_delete, SIZE_NAME, stdin)) service_to_delete[0] = '\0';
  remove_newline(service_to_delete);

  //int trovati[MAX_SERVIZI], conta_trovati = 0;
  int *found = malloc(MAX_SERVICES * sizeof(int));
  if (!found) {
	  printf("Error in memory allocation.\n");
	  return;
  }
  int count_found = 0;
  for (int i = 0; i < *numcont; i++) {
    if (strcmp(service[i], service_to_delete) == 0) {
      printf("\n[%d] Service: %s | Username: %s | Password: %s\n", count_found + 1, service[i], names[i], pass[i]);
      found[count_found++] = i;
    }
  }

  if (count_found == 0) {
    printf("Service not found.\n");
	free(found);
    return;
  }

  int choice = get_valid_number(1, count_found);
  int index = found[choice - 1];

  for (int j = index; j < *numcont - 1; j++) {
    strncpy(service[j], service[j + 1], SIZE_NAME -1);
    strncpy(names[j], names[j + 1], SIZE_NAME - 1);
    strncpy(pass[j], pass[j + 1], SIZE_PASSWD - 1);

    // Force \0.
    service[j][SIZE_NAME - 1] = '\0';
    names[j][SIZE_NAME - 1] = '\0';
    pass[j][SIZE_PASSWD - 1] = '\0';
  }
  (*numcont)--;
  free(found);
  printf("Service successfully deleted.\n");
}

// Function to save added/removed/changed services.
void save_services(char service[][SIZE_NAME], char names[][SIZE_NAME], char pass[][SIZE_PASSWD], int numcont) {

  if (access(FILE_PASSWD, F_OK) == 0) {
    /*if (chmod(FILE_PASSWD, PERM_WRITE) != 0) {
      perror("Chmod error.");
      exit(1);
    }*/
      set_writable(FILE_PASSWD);
  }
  
  FILE *file = fopen(FILE_PASSWD, "w");
  if (!file) {
    printf("Error while opening the file.\n");
    return;
  }

  char buf_service[ENCRYPTED_BUFFER];
  char buf_names[ENCRYPTED_BUFFER];
  char buf_pass[ENCRYPTED_BUFFER];

  for (int i = 0; i < numcont; i++) {

    // Copy in temporary buffers before encrypting.
    strncpy(buf_service, service[i], SIZE_NAME);
    strncpy(buf_names, names[i], SIZE_NAME);
    strncpy(buf_pass, pass[i], SIZE_PASSWD);

    // Encrypts temporary buffers, leaves original ones intact.
    encrypt_text(service[i], buf_service);
    encrypt_text(names[i], buf_names);
    encrypt_text(pass[i], buf_pass);

    // Original arrays are intact, no strcpy.
    fprintf(file, "%s %s %s\n", buf_service, buf_names, buf_pass);
  }

  fflush(file);
  fclose(file);

  /*if (chmod(FILE_PASSWD, PERM_READ) != 0) {
    perror("Chmod error.");
    exit(1);
  }*/
  set_readonly(FILE_PASSWD);
  
  printf("Services successfully saved.\n");
}

// Function to load services.
void load_services(char service[][SIZE_NAME], char names[][SIZE_NAME], char pass[][SIZE_PASSWD], int *numcont) {
  FILE *file = fopen(FILE_PASSWD, "r");
  if (!file) {
    printf("No file found. Creating a new one.\n");
    return;
  }

  *numcont = 0;
  char c_format[50];
  snprintf(c_format, sizeof(c_format), "%%%ds %%%ds %%%ds", SIZE_NAME - 1, SIZE_NAME -1, SIZE_PASSWD -1); // Avoids overflow.
  
  while (fscanf(file, c_format, service[*numcont], names[*numcont], pass[*numcont]) == 3) {
    decrypt_text(service[*numcont]);
    decrypt_text(names[*numcont]);
    decrypt_text(pass[*numcont]);
    (*numcont)++;
  }

  fclose(file);
  printf("Services successfully loaded.\n");
}

// Function to change a saved service (requires a valid number got with get_valid_number).
void change_service(char service[][SIZE_NAME], char names[][SIZE_NAME], char pass[][SIZE_PASSWD], int numcont) {
  char service_to_change[SIZE_NAME];
  
  printf("\nType the name of the service you want to change: ");
  if (!fgets(service_to_change, SIZE_NAME, stdin)) service_to_change[0] = '\0';
  remove_newline(service_to_change);

  //int trovati[MAX_SERVIZI], conta_trovati = 0;
  int *found = malloc(MAX_SERVICES * sizeof(int));
  if (!found) {
	  printf("Error in memory allocation.\n");
	  return;
  }
  int count_found = 0;
  
  for (int i = 0; i < numcont; i++) {
    if (strcmp(service[i], service_to_change) == 0) {
      printf("\n[%d] Service: %s | Username: %s | Password: %s\n", count_found + 1, service[i], names[i], pass[i]);
      found[count_found++] = i;
    }
  }

  if (count_found == 0) {
    printf("Service not found.\n");
	free(found);
    return;
  }

  int choice = get_valid_number(1, count_found);
  int index = found[choice - 1];

  char new_name[SIZE_NAME] = "", new_pass[SIZE_PASSWD] = "";

  printf("\nNew username (leave blank to maintain): ");
  if (!fgets(new_name, SIZE_NAME, stdin)) new_name[0] = '\0';
  remove_newline(new_name);

  printf("New password (leave blank to maintain): ");
  if (!fgets(new_pass, SIZE_PASSWD, stdin)) new_pass[0] = '\0';
  remove_newline(new_pass);

  if (strlen(new_name) > 0) strcpy(names[index], new_name);
  if (strlen(new_pass) > 0) strcpy(pass[index], new_pass);

  free(found);
  printf("Service successfully changed.\n");
}

// Function to create a program startup password used to create a unique hash saved in master.dat.
// WARNING: The function is case sensitive.
void create_master_password() {
  char password[MASTER_PASS_LEN];

  printf("Create a master password (remember it!): ");
  if (!fgets(password, sizeof(password), stdin)) password[0] = '\0';
  remove_newline(password);

  unsigned char salt[crypto_pwhash_SALTBYTES];
  randombytes_buf(salt, sizeof salt); // Salt is casual. Together with nonce makes the key (and the hash) linked to the password.

  unsigned char hash[HASH_LEN];
  if (crypto_pwhash(hash, HASH_LEN, password, strlen(password), salt, crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE, crypto_pwhash_ALG_DEFAULT) != 0) {
    printf("Error while hashing password.\n");
    exit(1);
  }

  if (access(FILE_MASTER, F_OK) == 0) {
    /*if (chmod(FILE_MASTER, PERM_WRITE) != 0) {
      perror("Chmod error.");
      exit(1);
    }*/
      set_writable(FILE_MASTER);
  }

  FILE *f = fopen(FILE_MASTER, "wb");
  if (!f) {
    printf("Error while creating master file.\n");
    sodium_memzero(password, sizeof password);
    return;
  }
  
  fwrite(salt, 1, sizeof salt, f);
  fwrite(hash, 1, sizeof hash, f);
  fflush(f);
  fclose(f);

  /*if (chmod(FILE_MASTER, PERM_READ) != 0) {
    perror("Chmod error.");
    exit(1);
  }*/
  set_readonly(FILE_MASTER);
 
  if (crypto_pwhash(key, crypto_secretbox_KEYBYTES, password, strlen(password), salt, crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE, crypto_pwhash_ALG_DEFAULT) != 0) {
    printf("Error in derivating the key.\n");
    exit(1);
  }

  sodium_memzero(password, sizeof password);
  printf("Master password created.\n");
}

// Function that reads the file master.dat and checks the uniqueness of the hash.
int check_master_password() {
  char password[MASTER_PASS_LEN];

  printf("Type the master password: ");
  if (!fgets(password, sizeof(password), stdin)) {
    printf("Error while reading the password.\n");
    return 0;
  }
  remove_newline(password);

  FILE *f = fopen(FILE_MASTER, "rb");
  if (!f) {
    printf("Master file not found.\n");
    sodium_memzero(password, sizeof password);
    return 0;
  }

  unsigned char salt[crypto_pwhash_SALTBYTES];
  unsigned char saved_hash[HASH_LEN];
  unsigned char calculated_hash[HASH_LEN];

  if (fread(salt, 1, sizeof salt, f) != sizeof salt) {
    fclose(f);
    return 0;
  }

  if (fread(saved_hash, 1, HASH_LEN, f) != HASH_LEN) {
    fclose(f);
    return 0;
  }

  fclose(f);

  if (crypto_pwhash(calculated_hash, sizeof calculated_hash, password, strlen(password), salt, crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE, crypto_pwhash_ALG_DEFAULT) != 0) {
    printf("Error while hashing password.\n");
    sodium_memzero(password, sizeof password);
    return 0;
  }

  if (sodium_memcmp(saved_hash, calculated_hash, sizeof saved_hash) != 0) {
    sodium_memzero(password, sizeof password);
    return 0;
  }

  if (crypto_pwhash(key, crypto_secretbox_KEYBYTES, password, strlen(password), salt, crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE, crypto_pwhash_ALG_DEFAULT) != 0) {
    printf("Error in derivating the key.\n");
    sodium_memzero(password, sizeof password);
    return 0;
  }

  sodium_memzero(password, sizeof password); // Clears the ram.
  return 1;
}

// Main
int main(void) {

#ifdef _WIN32
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);
#endif

  //setlocale(LC_ALL, "it_IT.UTF-8");
  setlocale(LC_ALL, "en_US.UTF-8");
  //setlocale(LC_ALL, "");
  
  if (sodium_init() < 0) {
    printf("Error while starting libsodium.\n"); // Starts libsodium library.
    return 1;
  }

  if (access(FILE_MASTER, F_OK) != 0) {
    create_master_password(); // Start and creates/requires a password.
  }

  int counter=5;

  for(counter=5; counter >= 0; counter--) {
  if (!check_master_password()) {
    printf("Wrong password. You have %i attempts left.\n", counter); // Show attempts if password's wrong.
  } else {
    counter=5;
    break; // Breaks when password's correct.
  }

  // Starts database reset.
    if (counter == 0) {
    printf("Reset database....\n");

    if(access(FILE_PASSWD, F_OK) == 0) {
    /*if (chmod(FILE_PASSWD, PERM_WRITE) != 0) {
      perror("Chmod error.");
      exit(1);
    }*/
        set_writable(FILE_PASSWD);
    }

    if(access(FILE_MASTER, F_OK) == 0) {
    /*if (chmod(FILE_MASTER, PERM_WRITE) != 0) {
      perror("Chmod error.");
      exit(1);
    }*/
        set_writable(FILE_MASTER);
    }

    FILE *fptrp = fopen(FILE_PASSWD, "wb");
    FILE *fptrm = fopen(FILE_MASTER, "wb");
    unsigned char zero[512];
    if (fptrp) {
      sodium_memzero(zero, sizeof zero);
      for(int i=0; i < MAX_SERVICES; i++) {
	fwrite(zero, 1, sizeof zero, fptrp); // Makes a zerofill.
      }
      fflush(fptrp);
      fclose(fptrp);
      remove(FILE_PASSWD); // Remove from filesystem.
    }
    if (fptrm) {
      sodium_memzero(zero, sizeof zero);
      for(int j=0; j < MAX_SERVICES; j++) {
	fwrite(zero, 1, sizeof zero, fptrm);
      }
      fflush(fptrm);
      fclose(fptrm);
      remove(FILE_MASTER);
    }
    printf("Database has been reset.\n");
    counter=5; // Reset counter.
    exit(1);
  }
  }

  
  printf("\n***********************************************************");
  printf("\nWARNING: TO WORK PROPERLY THE PROGRAM REQUIRES THE FILES master.dat AND password.dat IN THE SAME WORKING DIRECTORY (OTHERWISE NEW ONES WILL BE CREATED).");
  printf("\n***********************************************************");
  printf("\nTHE FILES password.dat AND master.dat MUSTN'T BE MODIFIED WITHOUT THIS PROGRAM (ANY EXTERNAL CHANGE WILL CAUSE PASSWORDS LOST).\n");
  printf("***********************************************************\n\n");
  
  // Dynamic memory allocation and starts the counter.
  char (*service)[SIZE_NAME] = calloc(MAX_SERVICES, SIZE_NAME * sizeof(char)); 
  char (*names)[SIZE_NAME] = calloc(MAX_SERVICES, SIZE_NAME * sizeof(char));
  char (*pass)[SIZE_PASSWD] = calloc(MAX_SERVICES, SIZE_PASSWD * sizeof(char));
  int numcont = 0;
  const int add = 1;
  const int save = 6;

  if (!service || !names || !pass) {
    printf("Error in memory allocation.\n"); // Verifies the memory allocation.
    return 1;
  }

  load_services(service, names, pass, &numcont);

  // Main menù.
  while (1) {
    printf("\nMenù:\n");
    printf("1. Add a service\n");
    printf("2. View services\n");
    printf("3. Find service\n");
    printf("4. Delete service\n");
    printf("5. Change service\n");
    printf("6. Save and exit\n");
    int choice = get_valid_number(add, save);

    switch (choice) {
    case 1:
      add_service(service, names, pass, &numcont);
      break;

    case 2:
      view_service(service, names, pass, numcont);
      break;

    case 3:
      find_service(service, names, pass, numcont);
      break;

    case 4:
      delete_service(service, names, pass, &numcont);
      break;

    case 5:
      change_service(service, names, pass, numcont);
      break;

    case 6:
      save_services(service, names, pass, numcont);

      // Empty the buffers.
      free(service);
      free(names);
      free(pass);
      return 0;

    default:
      printf("Invalid choice.\n");
    }
  }
}
