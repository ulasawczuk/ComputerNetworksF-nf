#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <algorithm>
#include <iostream>
#include <thread>

#define SOH 0x01 // Start of Header
#define EOT 0x04 // End of Transmission

void logMessage(const std::string &msg) {
    std::cout << "[Client] " << msg << std::endl;
}

void listenServer(int serverSocket) {
    int nread;
    char buffer[1025];

    logMessage("Listening for server messages...");

    while (true) {
        memset(buffer, 0, sizeof(buffer));
        nread = read(serverSocket, buffer, sizeof(buffer));

        if (nread == 0) { // Server has dropped us
            logMessage("Server closed connection. Exiting.");
            exit(0);
        } else if (nread > 0) {
            logMessage("Received message from server: " + std::string(buffer));
        } else {
            perror("Error reading from server");
            exit(1);
        }
    }
}

int main(int argc, char *argv[]) {
    int sock;
    struct sockaddr_in server;
    struct hostent *hp;
    char buffer[1025];
    bool finished = false;

    if (argc != 3) {
        printf("Usage: chat_client <server_ip> <server_port>\n");
        exit(1);
    }

    logMessage("Starting client...");

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Failed to open socket");
        exit(1);
    }
    logMessage("Socket created.");

    server.sin_family = AF_INET;
    hp = gethostbyname(argv[1]);
    if (hp == 0) {
        perror("Unknown host");
        close(sock);
        exit(1);
    }

    memcpy(&server.sin_addr, hp->h_addr, hp->h_length);
    server.sin_port = htons(atoi(argv[2]));

    logMessage("Connecting to server at " + std::string(argv[1]) + ":" + std::string(argv[2]) + "...");

    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("Failed to connect to server");
        close(sock);
        exit(1);
    }

    logMessage("Connected to server.");

    std::thread listenThread(listenServer, sock);

    while (!finished) {
        memset(buffer, 0, sizeof(buffer));
        fgets(buffer, sizeof(buffer), stdin);
        
        // Remove newline character from the input
        buffer[strcspn(buffer, "\n")] = 0;

        // Create the message with SOH and EOT
        std::string messageToSend;
        messageToSend += static_cast<char>(SOH);  // Add SOH
        messageToSend += buffer;                    // Add the actual message
        messageToSend += static_cast<char>(EOT);  // Add EOT

        if (write(sock, messageToSend.c_str(), messageToSend.length()) < 0) {
            perror("Failed to write to server");
            close(sock);
            exit(1);
        }
        logMessage("Sent message to server: " + std::string(buffer));
    }

    close(sock);
    listenThread.join();
    return 0;
}
