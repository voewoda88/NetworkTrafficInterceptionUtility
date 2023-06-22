#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <dirent.h>

#define PORT 8080
#define MAX_CLIENTS 1
#define BUF_SIZE 1024

bool isRunning = true;
pthread_t threads[MAX_CLIENTS];
int threadCount = 0;

bool flag = true;

const char* rootDirectory = "/home/voewoda/osisp/lab8/server";

void quit(int clientSocket, char response[])
{
    strcpy(response, "BYE\n");
    write(clientSocket, response, strlen(response));
    close(clientSocket);
}

void echoResponse(int clientSocket, char response[], char request[])
{
    char* echoText = request + 5;

    strcpy(response, "Echo response: ");
    strcat(response, echoText);
    strcat(response, "\n");
    write(clientSocket, response, strlen(response));
}

void listFiles(int clientSocket, char response[], char* path)
{
    DIR* directory = opendir(path);
    if (directory == NULL)
    {
        fprintf(stderr, "Error opening directory: %s\n", path);
        return;
    }

    struct dirent* entry;
    while ((entry = readdir(directory)) != NULL)
    {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0){
            continue;
        }

        char filePath[PATH_MAX];
        snprintf(filePath, sizeof(filePath), "%s/%s", path, entry->d_name);

        struct stat fileStat;
        if (lstat(filePath, &fileStat) == -1)
        {
            fprintf(stderr, "Error getting file status: %s\n", filePath);
            return;
        }

        if (S_ISDIR(fileStat.st_mode))
        {
            strcat(response, entry->d_name);
            strcat(response, "/\n");
        }
        else if (S_ISLNK(fileStat.st_mode))
        {
            char targetPath[PATH_MAX];
            ssize_t len = readlink(filePath, targetPath, sizeof(targetPath) - 1);
            if (len != -1)
            {
                targetPath[len] = '\0';
                strcat(response, entry->d_name);
                strcat(response, " --> ");
                strcat(response, targetPath);
                strcat(response, "\n");
            }
            else
            {
                fprintf(stderr, "Error reading symlink target: %s\n", filePath);
            }
        }
        else
        {
            strcat(response, entry->d_name);
            strcat(response, "\n");
        }
    }

    if(strlen(response) == 0)
        write(clientSocket, "Directory is empty\n", strlen("Directory is empty\n"));
    else
        write(clientSocket, response, strlen(response));

    closedir(directory);
}

char* changeDirectory(int clientSocket, char path[], char response[], char request[])
{
    char buffer[BUF_SIZE];
    memset(buffer, 0, BUF_SIZE);

    strcat(buffer, path);
    strcat(buffer, "/");
    strcat(buffer, request);

    if (chdir(buffer) == 0)
    {
        strcat(path, "/");
        strcat(path, request);
        flag = true;
    }
    else
    {
        strcat(response, "Error changing directory\n");
        write(clientSocket, response, strlen(response));
        flag = false;
    }

    return path;
}

void* clientHandler(void* arg)
{
    int clientSocket = *(int*)arg;
    char request[BUF_SIZE];
    char response[BUF_SIZE];
    ssize_t requestSize;

    char path[BUF_SIZE] = "/home/voewoda/osisp/lab8/server";

    printf("Connections in this moment: %d\n", threadCount);

    while(isRunning)
    {
        memset(request, 0, BUF_SIZE);
        memset(response, 0, BUF_SIZE);

        requestSize = read(clientSocket, request, sizeof(request));
        if (requestSize < 0)
        {
            fprintf(stderr, "Error reading from client\n");
            close(clientSocket);
            pthread_exit(NULL);
        }

        if (strncmp(request, "ECHO", 4) == 0)
            echoResponse(clientSocket, response, request);
        else if(strcmp(request, "INFO") == 0)
        {
            strcpy(response, "Welcome to the training server\n");
            write(clientSocket, response, strlen(response));
        }
        else if(strcmp(request, "LIST") == 0)
        {
            listFiles(clientSocket, response, path);
        }
        else if(strncmp(request, "CD", 2) == 0)
        {
            strcpy(path, changeDirectory(clientSocket, path, response, request + 3));
            if(flag == true)
            {
                strcat(response, "\n");
                write(clientSocket, response, strlen(response));
            }
        }
        else if (strcmp(request, "QUIT") == 0)
        {
            quit(clientSocket, response);
            threadCount--;
            pthread_exit(NULL);
        }
        else
        {
            strcpy(response, "Unknown command\n");
            write(clientSocket, response, strlen(response));
        }

    }

    quit(clientSocket, response);

    threadCount--;

    pthread_exit(NULL);
}

void hasActiveThreads()
{
    int i;
    for (i = threadCount - 1; i >= 0; i--)
        pthread_join(threads[i], NULL);

    threadCount = 0;
}

void handleSignal(int signal)
{
    isRunning = false;
    hasActiveThreads();
    exit(EXIT_SUCCESS);
}

int main(void)
{
    int serverSocket, clientSocket;
    struct sockaddr_in address;
    int addressLen = sizeof(address);

    if (signal(SIGINT, handleSignal) == SIG_ERR) 
    {
        printf("Failed to set signal handler for SIGINT\n");
        exit(EXIT_FAILURE);
    }

    if((serverSocket = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        fprintf(stderr, "Error creating server socket\n");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if(bind(serverSocket, (struct sockaddr*)&address, sizeof(address)) < 0)
    {
        fprintf(stderr, "Error binding server socket\n");
        exit(EXIT_FAILURE);
    }

    if(listen(serverSocket, MAX_CLIENTS) < 0)
    {
        fprintf(stderr, "Error listening for connections\n");
        exit(EXIT_FAILURE);
    }

    printf("Server started. Listening on port %d...\n", PORT);

    while(1)
    {
        clientSocket = accept(serverSocket, (struct sockaddr*)&address, (socklen_t*)&addressLen);

        if(threadCount < MAX_CLIENTS)
        {
            if (pthread_create(&threads[threadCount], NULL, clientHandler, &clientSocket) != 0) {
                fprintf(stderr, "Error creating thread\n");
                exit(EXIT_FAILURE);
            }
            threadCount++;
        }
        else
        {
            write(clientSocket, "Server is overflow, try again later\n", strlen("Server is overflow, try again later\n"));
            close(clientSocket);
        }
    }

    return 0;
}