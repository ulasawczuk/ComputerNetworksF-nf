# ComputerNetworksF-nf

This server application is designed to manage one-hop connections with other servers, handle commands from clients, and log its activities. The client maintains a communication with our server and sends it commands.

To compile the server and client code type "make" in terminal to activate the make file

Run the server by specifying a port number:
./tsamgroup12 <port>
The server will start listening for incoming connections on the specified port.

Run the client by specifing the IP address and a port number:
./client <server_ip> <server_port>


COMMAND OVERVIEW

1. HELO
Description: Used for the handshake process with connected servers.
Response: The server will respond with a list of currently connected servers, including each server's name, IP address, and port.
Behavior: On receiving a HELO message, the server marks the sender as a one-hop server and stores their connection details.
2. SERVERS
Description: Received to update the server's list of one-hop connected servers.
Action: Parses the list of servers from the command and updates the connectedServers list for the requesting client.
Response: Logs and stores details for each connected server (name, IP, port).
3. SENDMSG
Description: Sends a message to a specified server group.
Action: If the target server group is connected, sends the message directly. If the target isn’t connected, queues the message for later delivery.
Response: Acknowledges receipt with a confirmation message to the client.
4. GETMSG/GETMSGS
Description: Requests all queued messages for a specified server group.
Action: If messages are found in the queue for the target group, sends each as a SENDMSG command. Otherwise, informs the client that no messages exist.
Response: Sends either the messages or a notification that no messages are available.
5. KEEPALIVE
Description: Periodic check to maintain connection status.
Action: Logs the KEEPALIVE request, recording the message count received in the command.
6. LISTSERVERS
Description: Retrieves a list of all one-hop connected servers.
Action: Gathers connection details for each one-hop server.
Response: Sends a list of all servers in a SERVERS message format.
7. STATUSREQ
Description: Requests the status of each connected server.
Action: Compiles the number of messages for each group and builds a STATUSRESP message.
Response: Returns the message count for each connected server group.
8. STATUSRESP
Description: Processes a status response containing message counts for other groups.
Action: For each server in the STATUSRESP, if there are queued messages, initiates a GETMSG request to retrieve them.
Response: Sends GETMSG requests for groups with messages available and logs the retrieval.
9. UNKNOWN COMMAND
Description: If a command is unrecognized.
Action: Logs the unknown command for debugging purposes.
Response: No response sent to the client.

Additinally, the ERROR message that we process in STATUSRESP, it indicates an intrusive message and we don't process the rest of STATUSRESP.

Each server action, including message processing and command responses, is logged with timestamps to track server activity and communication events.