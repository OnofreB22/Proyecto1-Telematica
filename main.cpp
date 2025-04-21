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

// Helper function to decode URL-encoded strings
std::string urlDecode(const std::string& encoded) {
    std::string decoded;
    for (size_t i = 0; i < encoded.length(); ++i) {
        if (encoded[i] == '%') {
            if (i + 2 < encoded.length()) {
                std::string hex = encoded.substr(i + 1, 2);
                int ch;
                std::sscanf(hex.c_str(), "%x", &ch);
                decoded += static_cast<char>(ch);
                i += 2;
            }
        } else if (encoded[i] == '+') {
            decoded += ' ';
        } else {
            decoded += encoded[i];
        }
    }
    return decoded;
}

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
        
        // Decode the URI
        std::string decodedUri = urlDecode(uri);
        
        // Build the file path
        std::string filePath = documentRoot + decodedUri;
        
        // Check if path is a directory
        if (std::filesystem::is_directory(filePath)) {
            std::string errorBody = "<html><body>\n";
            errorBody += "<h1>400 Bad Request</h1>\n";
            errorBody += "<p>Directory listing is not allowed.</p>\n";
            errorBody += "<hr>\n";
            errorBody += "<address>" + SERVER_NAME + " Server</address>\n";
            errorBody += "</body></html>";
            
            sendResponse(clientSocket, StatusCode::BAD_REQUEST, "text/html", errorBody, method == "GET");
            logMessage("400 Bad Request: Directory access attempted: " + uri);
            return;
        }
        
        // Validate the path is within document root (prevent directory traversal)
        std::error_code ec;
        std::filesystem::path canonicalPath = std::filesystem::canonical(filePath, ec);
        std::filesystem::path canonicalRoot = std::filesystem::canonical(documentRoot);
        
        // Check if file exists and is within document root
        if (ec || !std::filesystem::exists(filePath) || 
            canonicalPath.string().compare(0, canonicalRoot.string().length(), 
            canonicalRoot.string()) != 0) {
            std::string errorBody = "<html><body>\n";
            errorBody += "<h1>404 Not Found</h1>\n";
            errorBody += "<p>The requested URL " + uri + " was not found on this server.</p>\n";
            errorBody += "<hr>\n";
            errorBody += "<address>" + SERVER_NAME + " Server</address>\n";
            errorBody += "</body></html>";
            
            sendResponse(clientSocket, StatusCode::NOT_FOUND, "text/html", errorBody, method == "GET");
            logMessage("404 Not Found: " + uri);
            return;
        }
        
        // Rest of the file handling code...
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
        if (request.find("Content-Type: multipart/form-data") != std::string::npos) {
            logMessage("Processing multipart form data");
            
            // Get Content-Length from headers
            size_t contentLengthPos = request.find("Content-Length: ");
            if (contentLengthPos == std::string::npos) {
                std::string errorBody = "<html><body><h1>400 Bad Request</h1><p>Missing Content-Length</p></body></html>";
                sendResponse(clientSocket, StatusCode::BAD_REQUEST, "text/html", errorBody, true);
                return;
            }
            
            size_t contentLengthEnd = request.find("\r\n", contentLengthPos);
            std::string contentLengthStr = request.substr(contentLengthPos + 16, contentLengthEnd - (contentLengthPos + 16));
            size_t contentLength = std::stoul(contentLengthStr);
            
            // Read the complete request with binary data
            std::vector<char> fullRequest(buffer, buffer + bytesRead);
            char tempBuffer[BUFFER_SIZE];
            
            // Continue reading until we get all the data
            while (fullRequest.size() < contentLength && 
                  (bytesRead = recv(clientSocket, tempBuffer, BUFFER_SIZE, 0)) > 0) {
                fullRequest.insert(fullRequest.end(), tempBuffer, tempBuffer + bytesRead);
            }

            // Convert to string for header processing only
            std::string requestStr(fullRequest.begin(), fullRequest.end());
            
            // Find boundary
            std::string boundaryPrefix = "boundary=";
            size_t boundaryPos = requestStr.find(boundaryPrefix);
            if (boundaryPos != std::string::npos) {
                boundaryPos += boundaryPrefix.length();
                std::string boundary;
                size_t boundaryEnd = requestStr.find("\r\n", boundaryPos);
                if (boundaryEnd != std::string::npos) {
                    boundary = requestStr.substr(boundaryPos, boundaryEnd - boundaryPos);
                    if (boundary.front() == '"' && boundary.back() == '"') {
                        boundary = boundary.substr(1, boundary.length() - 2);
                    }
                    
                    // Find content headers
                    std::string fullBoundary = "--" + boundary;
                    size_t contentStart = requestStr.find(fullBoundary);
                    if (contentStart != std::string::npos) {
                        size_t headersEnd = requestStr.find("\r\n\r\n", contentStart);
                        if (headersEnd != std::string::npos) {
                            // Extract filename
                            std::string headers = requestStr.substr(contentStart, headersEnd - contentStart);
                            size_t filenamePos = headers.find("filename=\"");
                            std::string filename = "uploaded_file";
                            
                            if (filenamePos != std::string::npos) {
                                filenamePos += 10;
                                size_t filenameEnd = headers.find("\"", filenamePos);
                                if (filenameEnd != std::string::npos) {
                                    filename = headers.substr(filenamePos, filenameEnd - filenamePos);
                                    // Get just the filename without path
                                    size_t lastSlash = filename.find_last_of("/\\");
                                    if (lastSlash != std::string::npos) {
                                        filename = filename.substr(lastSlash + 1);
                                    }
                                    
                                    // Replace spaces and special characters
                                    std::string sanitizedFilename;
                                    for (char c : filename) {
                                        if (c == ' ') {
                                            sanitizedFilename += '_';
                                        } else if (isalnum(c) || c == '.' || c == '-' || c == '_') {
                                            sanitizedFilename += c;
                                        }
                                    }
                                    filename = sanitizedFilename;
                                }
                            }
                            
                            // Find file data boundaries
                            size_t dataStart = headersEnd + 4;
                            std::string endBoundary = "\r\n--" + boundary + "--";
                            size_t dataEnd = requestStr.find(endBoundary, dataStart);
                            
                            if (dataEnd != std::string::npos) {
                                // Extract binary data directly from vector
                                std::vector<char> fileData(
                                    fullRequest.begin() + dataStart,
                                    fullRequest.begin() + dataEnd
                                );
                                
                                // Determine file type and subdirectory
                                std::string contentType = getContentType(filename);
                                std::string subDirectory;

                                if (contentType.find("image/") != std::string::npos) {
                                    subDirectory = "/images/";
                                } else if (contentType.find("video/") != std::string::npos) {
                                    subDirectory = "/videos/";
                                } else {
                                    subDirectory = "/others/";
                                }

                                // Save file
                                std::string saveFilePath = documentRoot + subDirectory + filename;
                                std::filesystem::create_directories(documentRoot + subDirectory);

                                std::ofstream outFile(saveFilePath, std::ios::binary);
                                if (outFile.is_open()) {
                                    outFile.write(fileData.data(), fileData.size());
                                    outFile.close();
                                    
                                    std::string responseBody = "<html><body><h1>File Uploaded</h1>";
                                    responseBody += "<p>File '" + filename + "' has been uploaded successfully.</p>";
                                    responseBody += "<p>File type: " + contentType + "</p>";
                                    responseBody += "<p><a href='" + subDirectory + filename + "'>View file</a></p>";
                                    responseBody += "</body></html>";
                                    
                                    sendResponse(clientSocket, StatusCode::OK, "text/html", responseBody, true);
                                    logMessage("File uploaded successfully: " + filename + " (Type: " + contentType + ")");
                                    return;
                                }
                            }
                        }
                    }
                }
            }
            
            // Error handling
            std::string errorBody = "<html><body><h1>400 Bad Request</h1>";
            errorBody += "<p>Error processing file upload</p></body></html>";
            sendResponse(clientSocket, StatusCode::BAD_REQUEST, "text/html", errorBody, true);
            logMessage("Failed to process file upload");
            return;
        }
        // Handle regular POST data as before
        size_t headerEnd = request.find("\r\n\r\n");
        if (headerEnd != std::string::npos) {
            std::string requestBody = request.substr(headerEnd + 4);
            std::string responseBody = "<html><body><h1>POST Successful</h1>";
            responseBody += "<p>Received data: " + requestBody + "</p></body></html>";
            sendResponse(clientSocket, StatusCode::OK, "text/html", responseBody, true);
        } else {
            std::string errorBody = "<html><body><h1>400 Bad Request</h1>";
            errorBody += "<p>Malformed POST request</p></body></html>";
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
