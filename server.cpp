//
// Simple chat server for TSAM-409
//
// Command line: ./chat_server <port> 
//
// Modified version: Without Client class
//P

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
#include <map>
#include <vector>
#include <list>
#include <iostream>
#include <sstream>
#include <thread>
#include <ctime>

#define BACKLOG 5          // Length of the queue of waiting connections


// Global data structures
std::map<int, std::string> clients;          // Map of client sockets to group IDs
std::map<std::string, std::list<std::string>> messageQueue;  // Messages per group

// Utility function to get the current timestamp as a string
std::string getTimestamp()
{
    time_t now = time(0);
    char buffer[100];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", localtime(&now));
    return std::string(buffer);
}

// Log the messages with timestamps
void logMessage(const std::string &msg)
{
    std::cout << "[" << getTimestamp() << "] " << msg << std::endl;
}

// Open socket for specified port.
// Returns -1 if unable to create the socket for any reason.
int open_socket(int portno)
{
    struct sockaddr_in sk_addr;   // Address settings for bind()
    int sock;                     // Socket opened for this port
    int set = 1;                  // For setsockopt

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("Failed to open socket");
        return -1;
    }

    // Turn on SO_REUSEADDR to allow the socket to be quickly reused after program exit.
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &set, sizeof(set)) < 0)
    {
        perror("Failed to set SO_REUSEADDR:");
    }

    memset(&sk_addr, 0, sizeof(sk_addr));
    sk_addr.sin_family = AF_INET;
    sk_addr.sin_addr.s_addr = INADDR_ANY;
    sk_addr.sin_port = htons(portno);

    // Bind the socket to listen for connections
    if (bind(sock, (struct sockaddr *)&sk_addr, sizeof(sk_addr)) < 0)
    {
        perror("Failed to bind to socket:");
        return -1;
    }

    return sock;
}

// Close a client's connection, remove from the client list, and tidy up select sockets afterwards.
void closeClient(int clientSocket, fd_set *openSockets, int *maxfds)
{
    printf("Client closed connection: %d\n", clientSocket);

    close(clientSocket);

    if (*maxfds == clientSocket)
    {
        for (const auto &p : clients)
        {
            *maxfds = std::max(*maxfds, p.first);
        }
    }

    // Remove from the list of open sockets
    FD_CLR(clientSocket, openSockets);
    clients.erase(clientSocket);
}

// Process command from client or server
void processCommand(int clientSocket, fd_set *openSockets, int *maxfds, char *buffer)
{
    std::vector<std::string> tokens;
    std::string token;
    std::stringstream stream(buffer);

    // Split command from client into tokens for parsing
    while (stream >> token)
        tokens.push_back(token);

    // Handle the commands from servers and clients
    if (tokens[0].compare("HELO") == 0 && tokens.size() == 2)
    {
        logMessage("HELO received from " + tokens[1]);
        std::string response = "SERVERS";
        for (const auto &client : clients)
        {
            response += "," + client.second;
        }
        send(clientSocket, response.c_str(), response.length(), 0);
    }
    else if (tokens[0].compare("KEEPALIVE") == 0 && tokens.size() == 2)
    {
        logMessage("KEEPALIVE received from client: " + std::to_string(clientSocket));
        // Respond or handle keepalive logic here
    }
    else if (tokens[0].compare("SENDMSG") == 0 && tokens.size() >= 3)
    {
        std::string toGroup = tokens[1];
        std::string fromGroup = clients[clientSocket];
        std::string message = tokens[2];

        for (auto i = tokens.begin() + 3; i != tokens.end(); ++i)
        {
            message += " " + *i;
        }

        logMessage("Message from " + fromGroup + " to " + toGroup + ": " + message);
        messageQueue[toGroup].push_back(fromGroup + ": " + message);

        std::string ack = "Message sent to " + toGroup;
        send(clientSocket, ack.c_str(), ack.length(), 0);
    }
    else if (tokens[0].compare("GETMSG") == 0 && tokens.size() == 2)
    {
        std::string group = tokens[1];
        if (!messageQueue[group].empty())
        {
            std::string message = messageQueue[group].front();
            messageQueue[group].pop_front();
            send(clientSocket, message.c_str(), message.length(), 0);
        }
        else
        {
            std::string noMessages = "No messages for group " + group;
            send(clientSocket, noMessages.c_str(), noMessages.length(), 0);
        }
    }
    else if (tokens[0].compare("LISTSERVERS") == 0)
    {
        std::string serverList = "Connected servers: ";
        for (const auto &client : clients)
        {
            serverList += client.second + ",";
        }
        send(clientSocket, serverList.c_str(), serverList.length() - 1, 0);
    }
    else
    {
        logMessage("Unknown command from client: " + std::string(buffer));
    }
}

int main(int argc, char *argv[])
{
    bool finished = false;
    int listenSock;                 // Socket for connections to server
    int clientSock;                 // Socket of connecting client
    fd_set openSockets;             // Current open sockets 
    fd_set readSockets;             // Socket list for select()        
    fd_set exceptSockets;           // Exception socket list
    int maxfds;                     // Passed to select() as max fd in set
    struct sockaddr_in client;
    socklen_t clientLen;
    char buffer[1025];              // buffer for reading from clients

    if (argc != 2)
    {
        printf("Usage: chat_server <ip port>\n");
        exit(0);
    }

    // Setup socket for server to listen to
    listenSock = open_socket(atoi(argv[1]));
    printf("Listening on port: %d\n", atoi(argv[1]));

    if (listen(listenSock, BACKLOG) < 0)
    {
        printf("Listen failed on port %s\n", argv[1]);
        exit(0);
    }
    else
    {
        FD_ZERO(&openSockets);
        FD_SET(listenSock, &openSockets);
        maxfds = listenSock;
    }

    while (!finished)
    {
        readSockets = exceptSockets = openSockets;
        memset(buffer, 0, sizeof(buffer));

        int n = select(maxfds + 1, &readSockets, NULL, &exceptSockets, NULL);

        if (n < 0)
        {
            perror("select failed - closing down\n");
            finished = true;
        }
        else
        {
            // Accept any new connections on the listening socket
            if (FD_ISSET(listenSock, &readSockets))
            {
                clientSock = accept(listenSock, (struct sockaddr *)&client, &clientLen);

                printf("Client connected on server: %d\n", clientSock);

                // Add new client to the list of open sockets
                FD_SET(clientSock, &openSockets);
                maxfds = std::max(maxfds, clientSock);

                // Assign a temporary group ID for the new client (can be changed later)
                clients[clientSock] = "Group" + std::to_string(clientSock);
            }

            // Now check for client messages
            for (const auto &pair : clients)
            {
                int clientSock = pair.first;
                if (FD_ISSET(clientSock, &readSockets))
                {
                    int bytes = recv(clientSock, buffer, sizeof(buffer), 0);
                    if (bytes > 0)
                    {
                        buffer[bytes] = '\0';
                        logMessage("Received message: " + std::string(buffer));
                        processCommand(clientSock, &openSockets, &maxfds, buffer);
                    }
                    else
                    {
                        closeClient(clientSock, &openSockets, &maxfds);
                    }
                }
            }
        }
    }
}
