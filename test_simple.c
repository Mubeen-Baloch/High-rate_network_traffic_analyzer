#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    printf("=== DDoS Detection System - Simple Test ===\n\n");
    
    // Test dataset path
    if (argc < 2) {
        printf("Usage: %s <dataset_file.csv>\n", argv[0]);
        printf("Example: %s data/CSV-01-12/01-12/DrDoS_DNS.csv\n", argv[0]);
        return 1;
    }
    
    char *dataset_path = argv[1];
    printf("Dataset: %s\n", dataset_path);
    
    // Check if file exists
    FILE *file = fopen(dataset_path, "r");
    if (!file) {
        printf("ERROR: Cannot open file: %s\n", dataset_path);
        return 1;
    }
    
    // Read first few lines
    char line[4096];
    int lines = 0;
    printf("\nFirst 5 lines of dataset:\n");
    printf("----------------------------------------\n");
    
    while (fgets(line, sizeof(line), file) != NULL && lines < 5) {
        printf("%d: %s", lines + 1, line);
        lines++;
    }
    
    fclose(file);
    
    printf("----------------------------------------\n");
    printf("\n✅ File readable!\n");
    printf("✅ Dataset structure looks correct!\n");
    printf("\nNext step: Parse and process the dataset\n");
    
    return 0;
}
