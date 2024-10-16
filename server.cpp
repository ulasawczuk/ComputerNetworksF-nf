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

#define BACKLOG 5              
#define SOH 0x01               
#define EOT 0x04              
#define DLE 0x10               

// Global data structures
std::map<int, std::string> clients; 
std::map<std::string, std::list<std::string>> messageQueue; 
std::map<int, std::string> messageBuffer; 

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

/*
// Helper function to perform byte-stuffing on a message
std::string byteStuffMessage(const std::string &message)
{
    std::string stuffedMessage;
    for (char c : message)
    {
        if (c == SOH || c == EOT || c == DLE)
        {
            stuffedMessage += DLE;  // Insert escape character before control chars
        }
        stuffedMessage += c;
    }
    return stuffedMessage;
}


// Helper function to remove byte-stuffing from a received message
std::string byteUnstuffMessage(const std::string &message)
{
    std::string unstuffedMessage;
    bool escapeNext = false;
    for (char c : message)
    {
        if (escapeNext)
        {
            unstuffedMessage += c;  // Add the actual escaped character
            escapeNext = false;
        }
        else if (c == DLE)
        {
            escapeNext = true;  // Mark the next character as escaped
        }
        else
        {
            unstuffedMessage += c;
        }
    }
    return unstuffedMessage;
}
*/

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
    messageBuffer.erase(clientSocket); // Clear any partial message buffer
}

// Process the completed message
// Process command from client or server
void processCommand(int clientSocket, fd_set *openSockets, int *maxfds, const std::string &command)
{
    std::vector<std::string> tokens;
    std::string token;
    std::stringstream stream(command);

    // Split command from client into tokens for parsing
    while (std::getline(stream, token, ','))
        tokens.push_back(token);

    // Handle the commands from servers and clients
    if (tokens[0].compare("HELO") == 0 && tokens.size() == 2)
    {
        std::string fromGroup = tokens[1];
        clients[clientSocket] = fromGroup;  // Register client with its group ID
        
        logMessage("HELO received from " + fromGroup);

        // Respond with SERVERS list
        std::string response = "SERVERS";
        for (const auto &client : clients)
        {
            response += "," + client.second + ",<IP>,<PORT>";  // You need to replace <IP> and <PORT> with real values
        }
        send(clientSocket, response.c_str(), response.length(), 0);
    }
    else if (tokens[0].compare("KEEPALIVE") == 0 && tokens.size() == 2)
    {
        std::string fromGroup = clients[clientSocket];
        int numMessages = std::stoi(tokens[1]);

        logMessage("KEEPALIVE received from client: " + fromGroup + ", No. of Messages: " + std::to_string(numMessages));

        // Handle keepalive logic if needed, e.g., updating a timestamp for the client
    }
    else if (tokens[0].compare("SENDMSG") == 0 && tokens.size() >= 4)
    {
        std::string toGroup = tokens[1];
        std::string fromGroup = tokens[2];
        std::string messageContent = tokens[3];

        for (size_t i = 4; i < tokens.size(); ++i)
        {
            messageContent += "," + tokens[i];
        }

        logMessage("Message from " + fromGroup + " to " + toGroup + ": " + messageContent);

        // Queue the message for the destination group
        messageQueue[toGroup].push_back(fromGroup + ": " + messageContent);

        // Acknowledge the message was received
        std::string ack = "Message sent to " + toGroup;
        send(clientSocket, ack.c_str(), ack.length(), 0);
    }
    else if (tokens[0].compare("GETMSGS") == 0 && tokens.size() == 2)
    {
        std::string group = tokens[1];
        if (!messageQueue[group].empty())
        {
            // Retrieve the next message for the group
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
    else if (tokens[0].compare("STATUSREQ") == 0)
    {
        logMessage("STATUSREQ received from client.");

        // Generate the STATUSRESP message
        std::string response = "STATUSRESP";
        for (const auto &queue : messageQueue)
        {
            response += "," + queue.first + "," + std::to_string(queue.second.size());
        }
        send(clientSocket, response.c_str(), response.length(), 0);
    }
    else
    {
        logMessage("Unknown command from client: " + command);
    }
}


// Read incoming data and accumulate it until a full message is received
void readClientData(int clientSocket, fd_set *openSockets, int *maxfds)
{
    char buffer[1024];
    int bytes = recv(clientSocket, buffer, sizeof(buffer), 0);

    if (bytes <= 0)
    {
        closeClient(clientSocket, openSockets, maxfds);
        return;
    }

    // Accumulate received data into the buffer for this client
    messageBuffer[clientSocket].append(buffer, bytes);

    // Process any complete messages (from SOH to EOT)
    std::string &clientData = messageBuffer[clientSocket];
    size_t startPos = clientData.find(SOH); // Find the start of a message

    while (startPos != std::string::npos)
    {
        size_t endPos = clientData.find(EOT, startPos + 1); // Find the end of the message
        if (endPos == std::string::npos)
        {
            break; // Incomplete message, wait for more data
        }

        // Extract and process the complete message
        std::string completeMessage = clientData.substr(startPos + 1, endPos - startPos - 1);
        processCommand(clientSocket, openSockets, maxfds, completeMessage);

        // Remove the processed message from the buffer
        clientData = clientData.substr(endPos + 1);
        startPos = clientData.find(SOH); // Look for another message
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
    std::map<int, std::string> partialMessages;  // For message accumulation

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

        // Wait for activity on sockets (using select)
        int n = select(maxfds + 1, &readSockets, NULL, &exceptSockets, NULL);

        if (n < 0)
        {
            perror("select failed - closing down\n");
            finished = true;
        }
        else
        {
            // Accept new connections on the listening socket
            if (FD_ISSET(listenSock, &readSockets))
            {
                clientSock = accept(listenSock, (struct sockaddr *)&client, &clientLen);

                printf("Client connected on server: %d\n", clientSock);

                // Add new client to the list of open sockets
                FD_SET(clientSock, &openSockets);
                maxfds = std::max(maxfds, clientSock);

                // Assign a temporary group ID for the new client
                clients[clientSock] = "Group" + std::to_string(clientSock);
            }

            // Process each client with pending data
            for (const auto &pair : clients)
            {
                int clientSock = pair.first;

                if (FD_ISSET(clientSock, &readSockets))
                {
                    int bytes = recv(clientSock, buffer, sizeof(buffer) - 1, 0);
                    if (bytes > 0)
                    {
                        buffer[bytes] = '\0';  // Null-terminate the received data
                        
                        // Accumulate message and handle byte-stuffing (assuming SOH = 0x01, EOT = 0x04)
                        std::string incomingData(buffer);
                        std::string &partialMessage = partialMessages[clientSock];

                        partialMessage += incomingData;

                        size_t startPos = partialMessage.find(0x01);  // Start of message
                        size_t endPos = partialMessage.find(0x04);    // End of message

                        // Process message if SOH and EOT are found
                        if (startPos != std::string::npos && endPos != std::string::npos && endPos > startPos)
                        {
                            std::string fullMessage = partialMessage.substr(startPos + 1, endPos - startPos - 1);  // Extract message content
                            partialMessage.erase(0, endPos + 1);  // Remove processed message

                            // Handle byte-stuffing by unescaping any stuffed characters
                            std::string unescapedMessage;
                            bool escapeNext = false;
                            for (char c : fullMessage)
                            {
                                if (escapeNext)
                                {
                                    unescapedMessage += c;
                                    escapeNext = false;
                                }
                                else if (c == 0x10)  // If escape character (byte-stuffing) found
                                {
                                    escapeNext = true;
                                }
                                else
                                {
                                    unescapedMessage += c;
                                }
                            }

                            // Process the fully accumulated and unescaped message
                            logMessage("Received message: " + unescapedMessage);
                            processCommand(clientSock, &openSockets, &maxfds, unescapedMessage);
                        }
                    }
                    else
                    {
                        // If recv returns 0, the client has disconnected
                        closeClient(clientSock, &openSockets, &maxfds);
                    }
                }
            }
        }
    }

    // Close listening socket when finished
    close(listenSock);
    return 0;
}
