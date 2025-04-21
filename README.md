# Servidor HTTP/1.1 - Proyecto de Telemática

## Introducción

Este proyecto consiste en la implementación de un servidor web compatible con el protocolo HTTP/1.1, desarrollado como parte del curso de Telemática. El objetivo principal es comprender en profundidad el funcionamiento de la capa de aplicación de la arquitectura TCP/IP, enfocándose específicamente en cómo opera el protocolo HTTP desde una perspectiva de programación en redes.

Un servidor web es un programa que entrega recursos (como páginas HTML, imágenes, archivos CSS, etc.) a los clientes que los solicitan mediante el protocolo HTTP. Este protocolo funciona como un lenguaje común para la comunicación entre el cliente (típicamente un navegador web) y el servidor.

Nuestro servidor implementa las siguientes características:
- Soporte para el protocolo HTTP/1.1
- Manejo de los métodos GET, HEAD y POST
- Procesamiento concurrente de peticiones mediante hilos
- Sistema de registro (logging) de todas las peticiones y respuestas
- Manejo de errores con códigos de estado HTTP apropiados (200, 400, 404)
- Capacidad para servir diferentes tipos de archivos (HTML, imágenes, videos, etc.)

## Configuración y Ejecución

### Requisitos
- Sistema operativo Linux
- Compilador g++ con soporte para C++17
- Make

### Compilación
El proyecto incluye un Makefile para facilitar la compilación. Para compilar el servidor:

```bash
make
```

Para limpiar los archivos compilados:
```bash
make clean
```

### Ejecución
El servidor requiere tres parámetros:
1. Puerto HTTP (ej: 8080)
2. Archivo de log (ej: server.log)
3. Directorio raíz de documentos (ej: ./webroot)

Para ejecutar el servidor:
```bash
./server 8080 server.log ./webroot
```

### Estructura de directorios
El servidor espera la siguiente estructura de directorios en webroot:
```
webroot/
├── index.html
├── images/
├── videos/
└── others/
```

Los archivos subidos se clasificarán automáticamente en estos directorios según su tipo:
- Imágenes en `/images/`
- Videos en `/videos/`
- Otros tipos de archivo en `/others/`

### Prueba
Una vez iniciado el servidor, puedes acceder a través de tu navegador web:
```
http://localhost:8080
```

## Desarrollo/Implementación

### Tecnologías utilizadas

El servidor fue implementado en C++ utilizando la API Berkeley Sockets para la comunicación en red. Se eligió C++ por sus ventajas en términos de rendimiento, su cercanía al hardware y su capacidad para manejar programación orientada a objetos, lo que facilitó la organización del código.

### Componentes principales del servidor

#### 1. Manejo de sockets

El servidor crea un socket utilizando la función `socket()`, lo configura para reutilizar direcciones, lo vincula a un puerto específico con `bind()`, y comienza a escuchar conexiones entrantes con `listen()`. Cuando llega una nueva conexión, se acepta con `accept()` y se crea un nuevo hilo para manejar la comunicación con ese cliente.

```cpp
// Create socket
int serverSocket = socket(AF_INET, SOCK_STREAM, 0);

// Set socket options to reuse address
int opt = 1;
setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

// Set up server address
struct sockaddr_in serverAddr;
serverAddr.sin_family = AF_INET;
serverAddr.sin_addr.s_addr = INADDR_ANY;
serverAddr.sin_port = htons(port);

// Bind socket to address
bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr));

// Listen for connections
listen(serverSocket, 10);
```

#### 2. Análisis de peticiones HTTP

El servidor analiza las peticiones HTTP entrantes para extraer el método (GET, HEAD o POST), la URI solicitada y la versión del protocolo HTTP. Este análisis se realiza en la función `parseRequest()`:

```cpp
void parseRequest(const std::string& request, std::string& method, std::string& uri, std::string& httpVersion) {
    // Find the first line of the request
    size_t endOfLine = request.find("\r\n");
    std::string requestLine = request.substr(0, endOfLine);
    
    // Parse the request line
    size_t firstSpace = requestLine.find(' ');
    method = requestLine.substr(0, firstSpace);
    
    size_t secondSpace = requestLine.find(' ', firstSpace + 1);
    uri = requestLine.substr(firstSpace + 1, secondSpace - firstSpace - 1);
    httpVersion = requestLine.substr(secondSpace + 1);
}
```

#### 3. Manejo de recursos

El servidor busca los recursos solicitados en el sistema de archivos local. Si el recurso existe, lo lee y lo envía al cliente. Si no existe, envía un error 404.

```cpp
std::string filePath = documentRoot + uri;
std::ifstream file(filePath, std::ios::binary | std::ios::ate);

if (!file.is_open()) {
    // File not found, send 404
    std::string errorBody = "<html><body><h1>404 Not Found</h1></body></html>";
    sendResponse(clientSocket, StatusCode::NOT_FOUND, "text/html", errorBody, true);
} else {
    // File found, read and send it
    std::streamsize fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<char> content(fileSize);
    file.read(content.data(), fileSize);
    std::string body(content.begin(), content.end());
    
    sendResponse(clientSocket, StatusCode::OK, getContentType(filePath), body, true);
}
```

#### 4. Generación de respuestas HTTP

El servidor genera respuestas HTTP apropiadas basadas en la petición del cliente y el resultado del procesamiento:

```cpp
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
}
```

#### 5. Concurrencia con hilos

Para manejar múltiples clientes simultáneamente, el servidor crea un nuevo hilo para cada conexión entrante:

```cpp
// Create a new thread to handle the client
threads.push_back(std::thread(handleClient, clientSocket));

// Detach the thread to let it run independently
threads.back().detach();
```

Esto permite que el servidor procese varias peticiones simultáneamente sin bloquear el hilo principal que acepta nuevas conexiones.

#### 6. Sistema de registro (logging)

El servidor registra todas las peticiones recibidas y las respuestas enviadas en un archivo de log especificado:

```cpp
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
```

### Capturas de pantalla del funcionamiento

![Servidor iniciado](https://via.placeholder.com/800x200?text=Servidor+iniciado+en+el+puerto+8080)
*Figura 1: Servidor HTTP iniciado en el puerto 8080*

![Petición GET exitosa](https://via.placeholder.com/800x400?text=Petición+GET+procesada+exitosamente)
*Figura 2: Navegador mostrando una petición GET procesada exitosamente*

![Archivo de log](https://via.placeholder.com/800x300?text=Archivo+de+log+mostrando+las+peticiones)
*Figura 3: Contenido del archivo de log mostrando las peticiones procesadas*

![Error 404](https://via.placeholder.com/800x300?text=Página+de+error+404)
*Figura 4: Página de error 404 cuando un recurso no es encontrado*

## Conclusiones

La implementación de este servidor HTTP/1.1 nos ha permitido comprender en profundidad el funcionamiento del protocolo HTTP y su papel en la arquitectura cliente-servidor de la web. A través de este proyecto, hemos aplicado conocimientos teóricos sobre redes, protocolos de comunicación y programación concurrente en un contexto práctico.

Algunas lecciones importantes aprendidas durante el desarrollo:

1. **Importancia de la especificación RFC**: El apego a la especificación RFC 2616 fue crucial para asegurar la compatibilidad con clientes HTTP estándar como navegadores web.

2. **Manejo de concurrencia**: El uso de hilos para manejar múltiples conexiones simultáneas demostró ser efectivo, aunque en un entorno de producción real, podrían ser necesarias técnicas más avanzadas como pools de hilos para evitar sobrecargas.

3. **Robustez en el manejo de errores**: Un servidor web debe ser extremadamente robusto ante peticiones malformadas o recursos inexistentes. El manejo adecuado de errores es tan importante como el manejo del caso exitoso.

4. **Eficiencia en entrada/salida**: El rendimiento de un servidor web depende en gran medida de cómo maneja las operaciones de entrada/salida. El uso de operaciones de lectura/escritura de archivos en modo binario y el manejo eficiente de los buffers fue crucial.

5. **Pruebas exhaustivas**: Probar un servidor web requiere considerar múltiples escenarios, desde peticiones bien formadas hasta intentos de explotación de vulnerabilidades.

Este proyecto ha sentado las bases para entender sistemas más complejos como servidores web de producción (Apache, Nginx) y cómo estos implementan características avanzadas como balanceo de carga, caché, y compresión de contenido.

## Referencias

1. RFC 2616: Hypertext Transfer Protocol -- HTTP/1.1. [https://datatracker.ietf.org/doc/rfc2616/](https://datatracker.ietf.org/doc/rfc2616/)

2. Beej's Guide to Network Programming. [https://beej.us/guide/bgnet/](https://beej.us/guide/bgnet/)

3. Linux Manual Page: socket(). [https://man7.org/linux/man-pages/man2/socket.2.html](https://man7.org/linux/man-pages/man2/socket.2.html)

4. TCP Server-Client implementation in C. [https://www.geeksforgeeks.org/tcp-server-client-implementation-in-c/](https://www.geeksforgeeks.org/tcp-server-client-implementation-in-c/)

5. Kurose, J. F., & Ross, K. W. (2021). Computer Networking: A Top-Down Approach (8th ed.). Pearson.

6. Stevens, W. R., Fenner, B., & Rudoff, A. M. (2003). UNIX Network Programming, Volume 1: The Sockets Networking API (3rd ed.). Addison-Wesley Professional.

7. Wireshark: Network Protocol Analyzer. [https://www.wireshark.org/](https://www.wireshark.org/)

8. Postman: API Development Environment. [https://www.postman.com/](https://www.postman.com/)
