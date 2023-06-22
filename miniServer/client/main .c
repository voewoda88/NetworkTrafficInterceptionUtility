#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define SERVER_IP "127.0.0.1"
#define PORT 8080
#define BUFFER_SIZE 1024

void processRequestsFromFile(const char* fileName, int clientSocket)
{
    ssize_t bytesRead;

    FILE* file = fopen(fileName, "r");
    if(file == NULL)
    {
        fprintf(stderr, "Error opening file: %s\n", fileName);
        return;
    }

    char buffer[BUFFER_SIZE];

    while(fgets(buffer, sizeof(buffer), file) != NULL)
    {
        printf("> ");
        printf("%s", buffer);

        buffer[strcspn(buffer, "\n")] = '\0';

        if (send(clientSocket, buffer, strlen(buffer), 0) < 0) {
            perror("Error sending command to server\n");
            exit(EXIT_FAILURE);
        }

        memset(buffer, 0, BUFFER_SIZE);

        bytesRead = read(clientSocket, buffer, sizeof(buffer));
        if (bytesRead < 0) {
            perror("Error reading server response\n");
            exit(EXIT_FAILURE);
        }

        if (strcmp(buffer, "\n") == 0)
            continue;
        else
            printf("%s", buffer);

        if (strcmp(buffer, "BYE\n") == 0)
            exit(EXIT_SUCCESS);
    }

    fclose(file);
}

int main()
{
    int clientSocket;
    struct sockaddr_in serverAddress;
    ssize_t bytesRead;
    char buffer[BUFFER_SIZE];
    char path[BUFFER_SIZE] = "/home/voewoda/osisp/lab8/server";

    if ((clientSocket = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("Error creating client socket\n");
        exit(EXIT_FAILURE);
    }

    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(PORT);

    if (inet_pton(AF_INET, SERVER_IP, &serverAddress.sin_addr) <= 0)
    {
        perror("Invalid address or address not supported\n");
        exit(EXIT_FAILURE);
    }

    if (connect(clientSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
    {
        perror("Error connecting to server\n");
        exit(EXIT_FAILURE);
    }

    printf("Connected to server. Enter commands (ECHO, QUIT, INFO, CD, LIST):\n");

    while (1)
    {
        memset(buffer, 0, BUFFER_SIZE);

        printf("> ");

        fgets(buffer, BUFFER_SIZE, stdin);
        buffer[strcspn(buffer, "\n")] = '\0';

        if(buffer[0] == '@')
        {
            char* fileName = &buffer[1];
            processRequestsFromFile(fileName, clientSocket);
        }
        else
        {
            if (send(clientSocket, buffer, strlen(buffer), 0) < 0) {
                perror("Error sending command to server\n");
                exit(EXIT_FAILURE);
            }

            memset(buffer, 0, BUFFER_SIZE);

            bytesRead = read(clientSocket, buffer, sizeof(buffer));
            if (bytesRead < 0) {
                perror("Error reading server response\n");
                exit(EXIT_FAILURE);
            }

            if (strcmp(buffer, "\n") == 0)
                continue;
            else
                printf("%s", buffer);

            if (strcmp(buffer, "BYE\n") == 0)
                exit(EXIT_SUCCESS);
        }
    }

    close(clientSocket);

    return 0;
}