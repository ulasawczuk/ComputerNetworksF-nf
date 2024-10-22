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
#include <string>
#include <mutex>
#include <vector>

#define BACKLOG 5
#define SOH 0x01
#define EOT 0x04
#define DLE 0x10
#define ESC 0x1B

// Global data structures
std::map<int, std::string> clients;
std::map<std::string, std::list<std::string>> messageQueue;
std::map<int, std::string> messageBuffer;
std::mutex serverMutex;

// Define a struct to hold server information
struct ServerInfo
{
    std::string name;                         // Server name
    std::string ip;                           // IP address
    int port;                                 // Port number
    bool HELOSent;                            // Helo bool
    std::vector<ServerInfo> connectedServers; // To hold connected server info

    // No constructer plese
};

std::map<int, ServerInfo> oneHopServers;

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

std::string stripSOHEOT(std::string &data)
{
    // Process any complete messages (from SOH to EOT)
    size_t startPos = data.find(SOH);
    std::string completeMessage;

    while (startPos != std::string::npos)
    {
        size_t endPos;
        size_t potEndPos = data.find(EOT, startPos + 1);
        if (potEndPos == std::string::npos)
        {
            break;
        }
        if (data[potEndPos - 1] != ESC)
        {
            endPos = potEndPos;
        }

        completeMessage = data.substr(startPos + 1, endPos - startPos - 1);
        logMessage("Complete message received from client : " + completeMessage);
        data = data.substr(endPos + 1);
        startPos = data.find(SOH);
    }
    return completeMessage;
}

// Set timeout for socket
void setSocketTimeout(int sock, int seconds)
{
    struct timeval timeout;
    timeout.tv_sec = seconds;
    timeout.tv_usec = 0;

    // Set the receive timeout
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
}

// Open socket for specified port.
// Returns -1 if unable to create the socket for any reason.
int open_socket(int portno)
{
    struct sockaddr_in sk_addr; // Address settings for bind()
    int sock;                   // Socket opened for this port
    int set = 1;                // For setsockopt

    logMessage("Attempting to open socket...");

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("Failed to open socket");
        return -1;
    }
    logMessage("Socket opened successfully.");

    // Turn on SO_REUSEADDR to allow the socket to be quickly reused after program exit.
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &set, sizeof(set)) < 0)
    {
        perror("Failed to set SO_REUSEADDR");
        return -1;
    }
    logMessage("SO_REUSEADDR set successfully.");

    memset(&sk_addr, 0, sizeof(sk_addr));
    sk_addr.sin_family = AF_INET;
    sk_addr.sin_addr.s_addr = INADDR_ANY;
    sk_addr.sin_port = htons(portno);

    // Bind the socket to listen for connections
    logMessage("Binding socket to port " + std::to_string(portno) + "...");
    if (bind(sock, (struct sockaddr *)&sk_addr, sizeof(sk_addr)) < 0)
    {
        perror("Failed to bind to socket");
        return -1;
    }
    logMessage("Socket bound to port " + std::to_string(portno) + " successfully.");

    return sock;
}

void sendKeepAlive()
{
    while (true)
    {
        std::this_thread::sleep_for(std::chrono::minutes(1)); // Wait for 1 minute

        std::lock_guard<std::mutex> lock(serverMutex); // Lock the mutex for safe access
        for (const auto &server : oneHopServers)
        {
            int serverSock = server.first;
            std::string group = server.second.name; // Use the server name as the group ID
            std::string keepAliveMessage = "\x01KEEPALIVE," + group + "\x04";

            logMessage("Sending KEEPALIVE message to server: " + group);
            send(serverSock, keepAliveMessage.c_str(), keepAliveMessage.length(), 0);
        }
    }
}

// Close a client's connection, remove from the client list, and tidy up select sockets afterwards.
void closeClient(int clientSocket, fd_set *openSockets, int *maxfds)
{
    logMessage("Closing client connection: " + std::to_string(clientSocket));
    close(clientSocket);

    if (*maxfds == clientSocket)
    {
        for (const auto &p : clients)
        {
            *maxfds = std::max(*maxfds, p.first);
        }
    }

    FD_CLR(clientSocket, openSockets);
    clients.erase(clientSocket);
    messageBuffer.erase(clientSocket); // Clear any partial message buffer
    logMessage("Client connection closed: " + std::to_string(clientSocket));
}

void parseServerResponse(const std::vector<std::string> &tokens, std::vector<ServerInfo> &connectedServers)
{
    if (tokens[0] == "SERVERS")
    {
        // Start parsing from the second token onward (since the first token is "SERVERS")
        for (size_t i = 1; i < tokens.size(); i += 3)
        {
            if (i + 2 < tokens.size()) // Ensure there are enough tokens to form a complete ServerInfo
            {
                std::string name = tokens[i];
                std::string ip = tokens[i + 1];
                int port = std::stoi(tokens[i + 2]);

                // Add the parsed server info to the connectedServers vector
                connectedServers.push_back({name, ip, port});
            }
        }
        logMessage("Parse server response finished correctly");
    }
    else
    {
        std::cerr << "Invalid response format" << std::endl;
    }
    logMessage("Parse server response finished correctly");
}

// Process the completed message and handle commands from clients.
void processCommand(int clientSocket, const std::string &command)
{
    std::vector<std::string> tokens;
    std::string token;
    std::stringstream stream(command);

    // // Split command from client into tokens for parsing
    // while (std::getline(stream, token, ','))
    // {
    //     tokens.push_back(token);
    //     // logMessage(token);
    // }

    while (std::getline(stream, token, ','))
    {

        // Check if the token contains a semicolon
        size_t semicolonPos = token.find(';');
        if (semicolonPos != std::string::npos)
        {
            // Split the token at the semicolon
            std::string beforeSemicolon = token.substr(0, semicolonPos);
            std::string afterSemicolon = token.substr(semicolonPos + 1);

            // Add part before semicolon, if not empty
            if (!beforeSemicolon.empty())
            {
                tokens.push_back(beforeSemicolon);
                logMessage(beforeSemicolon);
            }

            // Insert a special marker for the semicolon
            tokens.push_back("<SEMICOLON>");

            // Add part after semicolon, if any
            if (!afterSemicolon.empty())
            {
                tokens.push_back(afterSemicolon);
            }
        }
        else
        {
            // If no semicolon, add the token directly
            tokens.push_back(token);
        }
    }

    // Handle the commands from servers and clients
    if (tokens[0].compare("SERVERS") == 0)
    {
        std::vector<ServerInfo> connectedServers;

        parseServerResponse(tokens, connectedServers);
        oneHopServers[clientSocket].connectedServers = connectedServers;
        std::string response;
        for (const auto &server : connectedServers)
        {
            response += server.name + "," + server.ip + "," + std::to_string(server.port);
        }
        logMessage("This is what the server responed and what was saved " + response);
    }
    else if (tokens[0].compare("HELO") == 0 && tokens.size() == 2)
    {
        std::string fromGroup = tokens[1];
        clients[clientSocket] = fromGroup; // Register client with its group ID

        logMessage("HELO received from " + fromGroup);

        // Save NAME of new SERVER connection
        if (oneHopServers[clientSocket].name.compare("m") == 0)
        {
            oneHopServers[clientSocket].name = fromGroup;
        }
        // Answer with our own HELO message
        if (!oneHopServers[clientSocket].HELOSent)
        {
            // Send HELO message
            std::string ourGroup = "A5_12";
            std::string helloMessage = "\x01HELO," + ourGroup + "\x04"; // Add SOT (0x02) at the start and EOT (0x04) at the end

            send(clientSocket, helloMessage.c_str(), helloMessage.length(), 0);
            logMessage("Sent HELO message to " + fromGroup);
            oneHopServers[clientSocket].HELOSent = true;

            // Read response
            char buffer[5000];
            logMessage("Before recieving");
            int bytesRead = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
            std::string response(buffer);
            logMessage("After recieving" + response);
            // Reading the Servers
            if (bytesRead > 0)
            {
                // buffer[bytesRead] = '\0'; // Null-terminate the received data
                std::string response(buffer);

                logMessage("Received response from socket " + std::to_string(clientSocket) + " :" + response);

                std::string &data = messageBuffer[clientSocket];

                std::string completeMessage = stripSOHEOT(data);
                processCommand(clientSocket, completeMessage);
            }
            else
            {
                logMessage("Failed to receive response from " + oneHopServers[clientSocket].name);
            }
        }
        // Respond with SERVERS list
        logMessage("Sending our connections to " + fromGroup);
        std::string response = "SERVERS,";
        response += fromGroup + "," + oneHopServers[clientSocket].ip + "," + std::to_string(oneHopServers[clientSocket].port);

        for (const auto &server : oneHopServers)
        {

            if (server.second.name != fromGroup) // Avoid repeating the sender
            {
                response += ";" + server.second.name + "," + server.second.ip + "," + std::to_string(server.second.port);
            }
        }
        std::string bufferedResponse = "\x01" + response + "\x04"; // Add SOT (0x02) at the start and EOT (0x04) at the end
        send(clientSocket, bufferedResponse.c_str(), response.length(), 0);
    }
    else if (tokens[0].compare("KEEPALIVE") == 0 && tokens.size() == 2)
    {
        std::string fromGroup = clients[clientSocket];
        int numMessages = std::stoi(tokens[1]);

        logMessage("KEEPALIVE received from client: " + fromGroup + ", No. of Messages: " + std::to_string(numMessages));
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

        bool messageSent = false;

        for (std::map<int, ServerInfo>::iterator it = oneHopServers.begin(); it != oneHopServers.end(); ++it)
        {
            if (it->second.name == toGroup)
            {
                logMessage("Sending message immediately to " + toGroup + " via one-hop server.");

                std::string sendMsg = "SENDMSG," + toGroup + "," + fromGroup + "," + messageContent;
                send(it->first, sendMsg.c_str(), sendMsg.length(), 0);
                messageSent = true;
                break; // Exit once the message is sent
            }
        }

        if (!messageSent)
        {
            logMessage("Queueing message for " + toGroup);
            messageQueue[toGroup].push_back(command);
        }

        // Acknowledge the message was received
        std::string ack = "Message sent to " + toGroup;
        send(clientSocket, ack.c_str(), ack.length(), 0);
    }
    else if (tokens[0].compare("GETMSGS") == 0 && tokens.size() == 2)
    {
        std::string group = tokens[1];
        logMessage("GETMSGS request for group: " + group);

        // Check if there are messages in the queue for the specified group
        if (!messageQueue[group].empty())
        {
            // Send each message as a separate SENDMSG command
            while (!messageQueue[group].empty())
            {
                std::string message = messageQueue[group].front(); // Get the next message
                messageQueue[group].pop_front();                   // Remove it from the queue

                logMessage("Sending message: " + message + " to client " + std::to_string(clientSocket));
                send(clientSocket, message.c_str(), message.length(), 0); // Send the original SENDMSG command
            }
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
        for (const auto &server : oneHopServers)
        {
            const auto &serverInfo = server.second;
            std::string serverName = serverInfo.name;

            // Count the messages for the server's group name
            int messagesHeld = messageQueue[serverName].size();

            response += "," + serverName + "," + std::to_string(messagesHeld);
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
    char buffer[5000];
    int bytes = recv(clientSocket, buffer, sizeof(buffer), 0);

    if (bytes <= 0)
    {
        logMessage("Client " + std::to_string(clientSocket) + " disconnected or recv() failed.");
        closeClient(clientSocket, openSockets, maxfds);
        return;
    }

    // Accumulate received data into the buffer for this client
    messageBuffer[clientSocket].append(buffer, bytes);
    logMessage("Received " + std::to_string(bytes) + " bytes from client " + std::to_string(clientSocket));
    logMessage("Accumulated data from client " + std::to_string(clientSocket) + ": " + messageBuffer[clientSocket]);

    // Process any complete messages (from SOH to EOT)
    std::string &clientData = messageBuffer[clientSocket];

    std::string completeMessage = stripSOHEOT(clientData);
    processCommand(clientSocket, completeMessage);
}

// Function to connect to an instructor server and send a HELO message
void connectToInstructorServers()
{
    std::vector<std::pair<std::string, std::pair<int, std::string>>> instructorServers;
    instructorServers.push_back(std::make_pair("Instr_1", std::make_pair(5001, "130.208.246.249")));
    instructorServers.push_back(std::make_pair("Instr_2", std::make_pair(5002, "130.208.246.249")));
    instructorServers.push_back(std::make_pair("Instr_3", std::make_pair(5003, "130.208.246.249")));

    for (size_t i = 0; i < instructorServers.size(); ++i)
    {
        const std::string &name = instructorServers[i].first;
        int port = instructorServers[i].second.first;
        const std::string &ip = instructorServers[i].second.second;

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0)
        {
            perror("Failed to open socket for instructor server");
            continue;
        }

        sockaddr_in server;
        server.sin_family = AF_INET;
        inet_pton(AF_INET, ip.c_str(), &server.sin_addr);
        server.sin_port = htons(port);

        if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0)
        {
            perror("Failed to connect to instructor server");
            close(sock);
            continue;
        }

        logMessage("Connected to instructor server: " + name + " at " + ip + ":" + std::to_string(port));

        // Send HELO message
        std::string fromGroup = "A5_12";
        std::string helloMessage = "\x01HELO," + fromGroup + "\x04";
        send(sock, helloMessage.c_str(), helloMessage.length(), 0);
        logMessage("Sent HELO message to " + name);

        char buffer[5000];
        int bytesRead = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytesRead > 0)
        {
            buffer[bytesRead] = '\0'; // Null-terminate the received data
            std::string response(buffer);
            logMessage("Received response from port " + std::to_string(port) + ": " + response);

            // Extract the complete message
            std::string completeMessage = stripSOHEOT(response);

            ServerInfo newServer = {name, ip, port, true};
            oneHopServers[sock] = newServer;

            // Process the complete message
            processCommand(sock, completeMessage);
        }
    }
}

// Scanning 220 port for servers that are listening
void scanPorts(int omittedPort)
{
    const int startPort = 4000;
    const int endPort = 4200;

    for (int port = startPort; port <= endPort; ++port)
    {

        if (port == omittedPort)
        {
            logMessage("Omitting port: " + std::to_string(port));
            continue;
        }

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0)
        {
            perror("Failed to open socket for scanning");
            continue;
        }

        sockaddr_in server;
        server.sin_family = AF_INET;
        server.sin_addr.s_addr = INADDR_ANY; // Scan the local server
        server.sin_port = htons(port);

        // Set the timeout for the socket
        setSocketTimeout(sock, 3);

        // Attempt to connect to the server
        if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0)
        {
            // Connection failed, move to the next port
            close(sock);
            continue;
        }

        logMessage("Connected to local server on port: " + std::to_string(port));

        // Send HELO message
        std::string fromGroup = "A5_12"; // Adjust group name as necessary
        std::string helloMessage = "\x01HELO," + fromGroup + "\x04";
        send(sock, helloMessage.c_str(), helloMessage.length(), 0);
        logMessage("Sent HELO message to port: " + std::to_string(port));

        // Read response
        char buffer[5000];
        int bytesRead = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytesRead > 0)
        {
            buffer[bytesRead] = '\0'; // Null-terminate the received data
            std::string response(buffer);
            logMessage("Received response from port " + std::to_string(port) + ": " + response);

            sockaddr_in peerAddr;
            socklen_t peerAddrLen = sizeof(peerAddr);
            if (getpeername(sock, (struct sockaddr *)&peerAddr, &peerAddrLen) == 0)
            {
                char connectingServerIP[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &peerAddr.sin_addr, connectingServerIP, INET_ADDRSTRLEN);
                int connectingServerPort = ntohs(peerAddr.sin_port);

                // Create a new ServerInfo and add it to oneHopServers
                std::string missing = "m";
                ServerInfo newServer = {missing, std::string(connectingServerIP), connectingServerPort, true};
                oneHopServers[sock] = newServer;
            }
            else
            {
                perror("getpeername failed");
            }

            // Extract the complete message
            std::string completeMessage = stripSOHEOT(response);

            // Process the complete message
            processCommand(sock, completeMessage);
        }
        else
        {
            logMessage("No response or connection failed on port: " + std::to_string(port));
        }
    }
}

int main(int argc, char *argv[])
{
    bool finished = false;
    int listenSock;
    int clientSock;
    fd_set openSockets, readSockets, exceptSockets;
    int maxfds;
    struct sockaddr_in client;
    socklen_t clientLen;

    if (argc != 2)
    {
        printf("Usage: chat_server <ip port>\n");
        exit(0);
    }

    int serverPort = atoi(argv[1]);
    logMessage("Starting chat server...");

    listenSock = open_socket(atoi(argv[1]));
    if (listenSock < 0)
    {
        logMessage("Failed to start server.");
        exit(0);
    }

    logMessage("Listening on port: " + std::to_string(atoi(argv[1])));

    if (listen(listenSock, BACKLOG) < 0)
    {
        perror("Listen failed");
        exit(0);
    }

    FD_ZERO(&openSockets);
    FD_SET(listenSock, &openSockets);
    maxfds = listenSock;

    std::cout << "CONNECTING TO INSTUCTORS SERVERS" << std::endl;
    // Connect to specified instructor servers and send HELO messages
    connectToInstructorServers();

    std::cout << "DONE CONNECTING TO INSTUCTORS SERVERS" << std::endl;

    std::thread keepAliveThread(sendKeepAlive);
    keepAliveThread.detach(); // Detach the thread so it runs independently

    scanPorts(serverPort);

    logMessage("Waiting for connections...");

    while (!finished)
    {
        readSockets = exceptSockets = openSockets;
        int n = select(maxfds + 1, &readSockets, NULL, &exceptSockets, NULL);

        if (n < 0)
        {
            perror("Select failed");
            finished = true;
        }
        else
        {
            if (FD_ISSET(listenSock, &readSockets))
            {
                clientSock = accept(listenSock, (struct sockaddr *)&client, &clientLen);
                if (clientSock < 0)
                {
                    perror("Accept failed");
                    continue;
                }

                FD_SET(clientSock, &openSockets);
                maxfds = std::max(maxfds, clientSock);
                clients[clientSock] = "A5_" + std::to_string(clientSock);

                // Saving Client information if its the first HELO message
                char clientIP[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(client.sin_addr), clientIP, INET_ADDRSTRLEN);
                int clientPort = ntohs(client.sin_port);

                logMessage("Client connected on server: " + std::to_string(clientSock) +
                           " with IP: " + std::string(clientIP) +
                           " and port: " + std::to_string(clientPort));

                // Save the IP and port with the missing group name
                std::string missing = "m";
                ServerInfo newServer = {missing, std::string(clientIP), clientPort};
                oneHopServers[clientSock] = newServer;
            }

            for (const auto &pair : clients)
            {
                int clientSock = pair.first;
                if (FD_ISSET(clientSock, &readSockets))
                {
                    readClientData(clientSock, &openSockets, &maxfds);
                }
            }
        }
    }

    close(listenSock);
    logMessage("Server shutting down...");
    return 0;
}
