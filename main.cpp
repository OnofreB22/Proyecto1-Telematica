// main.cpp - HTTP Server implementation in C++

#include <iostream>
#include <string>
#include <fstream>
#include <thread>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <signal.h>
#include <filesystem>

// Global constants
const int BUFFER_SIZE = 4096;
const std::string SERVER_NAME = "TelematicaHTTP/1.0";

// Global variables
std::string documentRoot;
std::ofstream logFile;
bool serverRunning = true;

// HTTP status codes
enum class StatusCode {
    OK = 200,
    BAD_REQUEST = 400,
    NOT_FOUND = 404
};

// Forward declarations
std::string getStatusMessage(StatusCode code);
void handleClient(int clientSocket);
void logMessage(const std::string& message);
std::string getContentType(const std::string& filename);
void parseRequest(const std::string& request, std::string& method, 
                  std::string& uri, std::string& httpVersion);
void sendResponse(int clientSocket, StatusCode status, const std::string& contentType,
                 const std::string& body, bool includeBody);

// Signal handler for graceful shutdown
void signalHandler(int) {
    serverRunning = false;
    logMessage("Server shutting down...");
    logFile.close();
    exit(0);
}

int main(int argc, char* argv[]) {
    // Check command line arguments
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <HTTP_PORT> <Log_File> <DocumentRootFolder>" << std::endl;
        return 1;
    }

    int port = std::stoi(argv[1]);
    std::string logFilePath = argv[2];
    documentRoot = argv[3];

    // Open log file
    logFile.open(logFilePath, std::ios::app);
    if (!logFile.is_open()) {
        std::cerr << "Failed to open log file: " << logFilePath << std::endl;
        return 1;
    }

    // Set up signal handler for Ctrl+C
    signal(SIGINT, signalHandler);

    // Create socket
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0) {
        logMessage("Failed to create socket");
        return 1;
    }

    // Set socket options to reuse address
    int opt = 1;
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        logMessage("Failed to set socket options");
        return 1;
    }

    // Set up server address
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(port);

    // Bind socket to address
    if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        logMessage("Failed to bind socket to address");
        return 1;
    }

    // Listen for connections
    if (listen(serverSocket, 10) < 0) {
        logMessage("Failed to listen on socket");
        return 1;
    }

    logMessage("Server started on port " + std::to_string(port));
    std::cout << "Server running on port " << port << "..." << std::endl;

    // Vector to keep track of threads
    std::vector<std::thread> threads;

    // Accept and handle connections
    while (serverRunning) {
        struct sockaddr_in clientAddr;
        socklen_t clientAddrLen = sizeof(clientAddr);
        
        // Accept a new connection
        int clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientAddrLen);
        if (clientSocket < 0) {
            logMessage("Failed to accept connection");
            continue;
        }

        // Get client info
        char clientIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(clientAddr.sin_addr), clientIP, INET_ADDRSTRLEN);
        logMessage("New connection from " + std::string(clientIP) + ":" + 
                  std::to_string(ntohs(clientAddr.sin_port)));

        // Create a new thread to handle the client
        threads.push_back(std::thread(handleClient, clientSocket));
        
        // Detach the thread to let it run independently
        threads.back().detach();
    }

    // Clean up
    close(serverSocket);
    logFile.close();
    return 0;
}

// Handle client connection in a separate thread
void handleClient(int clientSocket) {
    char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);
    
    // Receive client request
    int bytesRead = recv(clientSocket, buffer, BUFFER_SIZE - 1, 0);
    if (bytesRead < 0) {
        logMessage("Error reading from socket");
        close(clientSocket);
        return;
    }
    
    // Log the request
    std::string request(buffer);
    logMessage("Request received:\n" + request);
    
    // Parse the request
    std::string method, uri, httpVersion;
    parseRequest(request, method, uri, httpVersion);
    
    // Check if the HTTP version is valid
    if (httpVersion != "HTTP/1.1") {
        std::string errorBody = "<html><body><h1>400 Bad Request</h1><p>Invalid HTTP version</p></body></html>";
        sendResponse(clientSocket, StatusCode::BAD_REQUEST, "text/html", errorBody, true);
        close(clientSocket);
        return;
    }
    
    // Handle different HTTP methods
    if (method == "GET" || method == "HEAD") {
        // Default to index.html if root is requested
        if (uri == "/") {
            uri = "/index.html";
        }
        
        // Build the file path
        std::string filePath = documentRoot + uri;
        
        // Check if file exists
        std::ifstream file(filePath, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            std::string errorBody = "<html><body><h1>404 Not Found</h1><p>The requested resource was not found on this server.</p></body></html>";
            sendResponse(clientSocket, StatusCode::NOT_FOUND, "text/html", errorBody, method == "GET");
        } else {
            // Get file size and prepare to read it
            std::streamsize fileSize = file.tellg();
            file.seekg(0, std::ios::beg);
            
            // Read file content
            std::vector<char> content(fileSize);
            if (file.read(content.data(), fileSize)) {
                std::string body(content.begin(), content.end());
                std::string contentType = getContentType(filePath);
                
                // Send response with or without body depending on the method
                sendResponse(clientSocket, StatusCode::OK, contentType, body, method == "GET");
            } else {
                std::string errorBody = "<html><body><h1>500 Internal Server Error</h1><p>Error reading file.</p></body></html>";
                sendResponse(clientSocket, StatusCode::BAD_REQUEST, "text/html", errorBody, method == "GET");
            }
        }
    } else if (method == "POST") {
        // Extract the body from the request
        size_t headerEnd = request.find("\r\n\r\n");
        if (headerEnd != std::string::npos) {
            std::string requestBody = request.substr(headerEnd + 4);
            // Process the POST data (for this example, we'll just echo it back)
            std::string responseBody = "<html><body><h1>POST Successful</h1><p>Received data: " + requestBody + "</p></body></html>";
            sendResponse(clientSocket, StatusCode::OK, "text/html", responseBody, true);
        } else {
            std::string errorBody = "<html><body><h1>400 Bad Request</h1><p>Malformed POST request</p></body></html>";
            sendResponse(clientSocket, StatusCode::BAD_REQUEST, "text/html", errorBody, true);
        }
    } else {
        // Method not supported
        std::string errorBody = "<html><body><h1>400 Bad Request</h1><p>Method not supported</p></body></html>";
        sendResponse(clientSocket, StatusCode::BAD_REQUEST, "text/html", errorBody, true);
    }
    
    // Close the connection
    close(clientSocket);
}

// Parse an HTTP request into method, URI, and HTTP version
void parseRequest(const std::string& request, std::string& method, std::string& uri, std::string& httpVersion) {
    // Find the first line of the request
    size_t endOfLine = request.find("\r\n");
    if (endOfLine == std::string::npos) {
        method = "";
        uri = "";
        httpVersion = "";
        return;
    }
    
    std::string requestLine = request.substr(0, endOfLine);
    
    // Parse the request line
    size_t firstSpace = requestLine.find(' ');
    if (firstSpace == std::string::npos) {
        method = "";
        uri = "";
        httpVersion = "";
        return;
    }
    
    method = requestLine.substr(0, firstSpace);
    
    size_t secondSpace = requestLine.find(' ', firstSpace + 1);
    if (secondSpace == std::string::npos) {
        uri = "";
        httpVersion = "";
        return;
    }
    
    uri = requestLine.substr(firstSpace + 1, secondSpace - firstSpace - 1);
    httpVersion = requestLine.substr(secondSpace + 1);
}

// Send HTTP response
void sendResponse(int clientSocket, StatusCode status, const std::string& contentType,
                 const std::string& body, bool includeBody) {
    // Build the response header
    std::string response = "HTTP/1.1 " + std::to_string(static_cast<int>(status)) + " " + 
                           getStatusMessage(status) + "\r\n";
    response += "Server: " + SERVER_NAME + "\r\n";
    response += "Content-Type: " + contentType + "\r\n";
    response += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    response += "Connection: close\r\n";
    response += "\r\n";
    
    // Add the body if needed (for GET but not for HEAD)
    if (includeBody) {
        response += body;
    }
    
    // Send the response
    send(clientSocket, response.c_str(), response.size(), 0);
    
    // Log the response
    logMessage("Response sent with status code " + std::to_string(static_cast<int>(status)));
}

// Get content type based on file extension
std::string getContentType(const std::string& filename) {
    size_t dotPos = filename.find_last_of(".");
    if (dotPos == std::string::npos) {
        return "application/octet-stream";
    }
    
    std::string extension = filename.substr(dotPos + 1);
    if (extension == "html" || extension == "htm") {
        return "text/html";
    } else if (extension == "txt") {
        return "text/plain";
    } else if (extension == "css") {
        return "text/css";
    } else if (extension == "js") {
        return "application/javascript";
    } else if (extension == "jpg" || extension == "jpeg") {
        return "image/jpeg";
    } else if (extension == "png") {
        return "image/png";
    } else if (extension == "gif") {
        return "image/gif";
    } else if (extension == "mp4") {
        return "video/mp4";
    } else if (extension == "webm") {
        return "video/webm";
    } else if (extension == "ogg") {
        return "video/ogg";
    } else if (extension == "mp3") {
        return "audio/mpeg";
    } else if (extension == "pdf") {
        return "application/pdf";
    } else {
        return "application/octet-stream";
    }
}

// Get status message for a status code
std::string getStatusMessage(StatusCode code) {
    switch (code) {
        case StatusCode::OK:
            return "OK";
        case StatusCode::BAD_REQUEST:
            return "Bad Request";
        case StatusCode::NOT_FOUND:
            return "Not Found";
        default:
            return "Unknown";
    }
}

// Log a message to the log file
void logMessage(const std::string& message) {
    // Get current time
    time_t now = time(0);
    struct tm* timeinfo = localtime(&now);
    char timestamp[80];
    strftime(timestamp, sizeof(timestamp), "[%d-%m-%Y %H:%M:%S] ", timeinfo);
    
    // Log to file
    logFile << timestamp << message << std::endl;
    logFile.flush();
}
