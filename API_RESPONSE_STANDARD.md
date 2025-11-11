# API Response Standard

## Resumen

Se ha implementado un estándar unificado para todas las respuestas de la API, tanto exitosas como de error, con códigos de error categorizados y Request ID para trazabilidad.

---

## Estructura de Respuestas

### 1. Respuestas Exitosas

**Formato:**
```json
{
  "status": "success",
  "statusCode": 200,
  "data": { ... },
  "requestId": "a1b2c3d4-e5f6-7890-g1h2-i3j4k5l6m7n8"
}
```

**Ejemplo - Login Exitoso:**
```json
{
  "status": "success",
  "statusCode": 200,
  "data": {
    "accessToken": "eyJhbGciOiJIUzI1NiIs...",
    "refreshToken": "550e8400-e29b-41d4-a716-446655440000",
    "tokenType": "Bearer",
    "expiresIn": 3600000
  },
  "requestId": "f47ac10b-58cc-4372-a567-0e02b2c3d479"
}
```

### 2. Respuestas de Error

**Formato:**
```json
{
  "status": "error",
  "statusCode": 404,
  "error": {
    "code": "RESOURCE_NOT_FOUND",
    "message": "The requested resource was not found.",
    "details": "The user with the ID '12345' does not exist in our records.",
    "timestamp": "2023-12-08T12:30:45Z",
    "path": "/api/v1/users/12345"
  },
  "requestId": "a1b2c3d4-e5f6-7890-g1h2-i3j4k5l6m7n8"
}
```

### 3. Respuestas de Error de Validación

**Formato:**
```json
{
  "status": "error",
  "statusCode": 400,
  "error": {
    "code": "VALIDATION_FAILED",
    "message": "Input validation failed",
    "details": "One or more fields have validation errors",
    "timestamp": "2023-12-08T12:30:45Z",
    "path": "/api/v1/auth",
    "fieldErrors": {
      "username": ["Username must be between 3 and 50 characters"],
      "password": ["Password must be at least 6 characters"]
    }
  },
  "requestId": "b2c3d4e5-f6g7-8901-h2i3-j4k5l6m7n8o9"
}
```

---

## Códigos de Error

### Categorías

#### Autenticación y Autorización (1xxx)

| Código | Mensaje | HTTP Status |
|--------|---------|-------------|
| `AUTH_1001` | Invalid username or password | 401 |
| `AUTH_1002` | User not found | 404 |
| `AUTH_1003` | Authentication failed | 401 |
| `AUTH_1004` | Access denied to the requested resource | 403 |
| `AUTH_1005` | Insufficient permissions | 403 |

#### Tokens JWT (2xxx)

| Código | Mensaje | HTTP Status |
|--------|---------|-------------|
| `TOKEN_2001` | Invalid or malformed JWT token | 401 |
| `TOKEN_2002` | JWT token has expired | 401 |
| `TOKEN_2003` | JWT token signature validation failed | 401 |
| `TOKEN_2004` | Malformed JWT token format | 400 |

#### Refresh Tokens (3xxx)

| Código | Mensaje | HTTP Status |
|--------|---------|-------------|
| `REFRESH_3001` | Refresh token not found | 404 |
| `REFRESH_3002` | Refresh token has expired | 401 |
| `REFRESH_3003` | Invalid refresh token | 401 |

#### Validación (4xxx)

| Código | Mensaje | HTTP Status |
|--------|---------|-------------|
| `VALIDATION_4001` | Input validation failed | 400 |
| `VALIDATION_4002` | Invalid request body format | 400 |
| `VALIDATION_4003` | Required field is missing | 400 |
| `VALIDATION_4004` | Field format is invalid | 400 |

#### Recursos (5xxx)

| Código | Mensaje | HTTP Status |
|--------|---------|-------------|
| `RESOURCE_5001` | The requested resource was not found | 404 |
| `RESOURCE_5002` | Resource already exists | 409 |

#### Servidor (9xxx)

| Código | Mensaje | HTTP Status |
|--------|---------|-------------|
| `SERVER_9001` | An unexpected internal server error occurred | 500 |
| `SERVER_9002` | Service temporarily unavailable | 503 |
| `SERVER_9003` | Bad request | 400 |

---

## Request ID

### Generación

Cada request recibe un ID único (UUID v4) generado automáticamente:

```
f47ac10b-58cc-4372-a567-0e02b2c3d479
```

### Propagación

1. **Cliente puede enviar:** Header `X-Request-Id`
2. **Servidor genera si no existe:** UUID automático
3. **Servidor retorna:** Header `X-Request-Id` + campo en respuesta JSON
4. **Logging:** Incluido en todos los logs con formato `[requestId]`

### Ejemplo de Logging

```
2023-12-08 12:30:45 WARN [f47ac10b-58cc-4372-a567-0e02b2c3d479] User not found: admin123
2023-12-08 12:31:22 INFO [a1b2c3d4-e5f6-7890-g1h2-i3j4k5l6m7n8] Authentication successful for user: operator
```

---

## Ejemplos de Respuestas

### Ejemplo 1: Autenticación Exitosa

**Request:**
```http
POST /api/v1/auth HTTP/1.1
Content-Type: application/json

{
  "username": "admin",
  "password": "adminpass"
}
```

**Response:**
```json
HTTP/1.1 200 OK
X-Request-Id: f47ac10b-58cc-4372-a567-0e02b2c3d479
Content-Type: application/json

{
  "status": "success",
  "statusCode": 200,
  "data": {
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "550e8400-e29b-41d4-a716-446655440000",
    "tokenType": "Bearer",
    "expiresIn": 3600000
  },
  "requestId": "f47ac10b-58cc-4372-a567-0e02b2c3d479"
}
```

### Ejemplo 2: Credenciales Inválidas

**Request:**
```http
POST /api/v1/auth HTTP/1.1
Content-Type: application/json

{
  "username": "admin",
  "password": "wrongpassword"
}
```

**Response:**
```json
HTTP/1.1 401 Unauthorized
X-Request-Id: b2c3d4e5-f6g7-8901-h2i3-j4k5l6m7n8o9
Content-Type: application/json

{
  "status": "error",
  "statusCode": 401,
  "error": {
    "code": "AUTH_1001",
    "message": "Invalid username or password",
    "timestamp": "2023-12-08T12:30:45.123Z",
    "path": "/api/v1/auth"
  },
  "requestId": "b2c3d4e5-f6g7-8901-h2i3-j4k5l6m7n8o9"
}
```

### Ejemplo 3: Error de Validación

**Request:**
```http
POST /api/v1/auth HTTP/1.1
Content-Type: application/json

{
  "username": "ab",
  "password": "123"
}
```

**Response:**
```json
HTTP/1.1 400 Bad Request
X-Request-Id: c3d4e5f6-g7h8-9012-i3j4-k5l6m7n8o9p0
Content-Type: application/json

{
  "status": "error",
  "statusCode": 400,
  "error": {
    "code": "VALIDATION_4001",
    "message": "Input validation failed",
    "details": "One or more fields have validation errors",
    "timestamp": "2023-12-08T12:30:45.123Z",
    "path": "/api/v1/auth",
    "fieldErrors": {
      "username": [
        "Username must be between 3 and 50 characters"
      ],
      "password": [
        "Password must be between 6 and 100 characters"
      ]
    }
  },
  "requestId": "c3d4e5f6-g7h8-9012-i3j4-k5l6m7n8o9p0"
}
```

### Ejemplo 4: Token Expirado

**Request:**
```http
GET /api/v1/private/admin/health HTTP/1.1
Authorization: Bearer eyJhbGciOiJIUzI1NiIs... (expired token)
```

**Response:**
```json
HTTP/1.1 401 Unauthorized
X-Request-Id: d4e5f6g7-h8i9-0123-j4k5-l6m7n8o9p0q1
Content-Type: application/json

{
  "status": "error",
  "statusCode": 401,
  "error": {
    "code": "TOKEN_2002",
    "message": "JWT token has expired",
    "details": "Token expired at: 2023-12-08T11:30:45Z",
    "timestamp": "2023-12-08T12:30:45.123Z",
    "path": "/api/v1/private/admin/health"
  },
  "requestId": "d4e5f6g7-h8i9-0123-j4k5-l6m7n8o9p0q1"
}
```

### Ejemplo 5: Acceso Denegado

**Request:**
```http
GET /api/v1/private/admin/health HTTP/1.1
Authorization: Bearer <token_de_usuario_operator>
```

**Response:**
```json
HTTP/1.1 403 Forbidden
X-Request-Id: e5f6g7h8-i9j0-1234-k5l6-m7n8o9p0q1r2
Content-Type: application/json

{
  "status": "error",
  "statusCode": 403,
  "error": {
    "code": "AUTH_1004",
    "message": "Access denied to the requested resource",
    "details": "You don't have permission to access this resource",
    "timestamp": "2023-12-08T12:30:45.123Z",
    "path": "/api/v1/private/admin/health"
  },
  "requestId": "e5f6g7h8-i9j0-1234-k5l6-m7n8o9p0q1r2"
}
```

### Ejemplo 6: Refresh Token Expirado

**Request:**
```http
POST /api/v1/refresh HTTP/1.1
Content-Type: application/json

{
  "refreshToken": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response:**
```json
HTTP/1.1 401 Unauthorized
X-Request-Id: f6g7h8i9-j0k1-2345-l6m7-n8o9p0q1r2s3
Content-Type: application/json

{
  "status": "error",
  "statusCode": 401,
  "error": {
    "code": "REFRESH_3002",
    "message": "Refresh token has expired",
    "details": "Token expired at: 2023-12-01T12:30:45Z. Please login again",
    "timestamp": "2023-12-08T12:30:45.123Z",
    "path": "/api/v1/refresh"
  },
  "requestId": "f6g7h8i9-j0k1-2345-l6m7-n8o9p0q1r2s3"
}
```

### Ejemplo 7: Error Interno del Servidor

**Request:**
```http
POST /api/v1/auth HTTP/1.1
Content-Type: application/json

{
  "username": "admin",
  "password": "adminpass"
}
```

**Response:**
```json
HTTP/1.1 500 Internal Server Error
X-Request-Id: g7h8i9j0-k1l2-3456-m7n8-o9p0q1r2s3t4
Content-Type: application/json

{
  "status": "error",
  "statusCode": 500,
  "error": {
    "code": "SERVER_9001",
    "message": "An unexpected internal server error occurred",
    "details": "An unexpected error occurred. Please try again later or contact support with request ID: g7h8i9j0-k1l2-3456-m7n8-o9p0q1r2s3t4",
    "timestamp": "2023-12-08T12:30:45.123Z",
    "path": "/api/v1/auth"
  },
  "requestId": "g7h8i9j0-k1l2-3456-m7n8-o9p0q1r2s3t4"
}
```

---

## Implementación

### Componentes Creados

#### 1. DTOs

**ErrorCode.java** - Enum con todos los códigos de error:
```java
public enum ErrorCode {
    INVALID_CREDENTIALS("AUTH_1001", "Invalid username or password"),
    USER_NOT_FOUND("AUTH_1002", "User not found"),
    // ... etc
}
```

**ErrorDetail.java** - Detalle del error:
```java
public record ErrorDetail(
    String code,
    String message,
    String details,
    Instant timestamp,
    String path
)
```

**ApiErrorResponse.java** - Respuesta de error completa:
```java
public record ApiErrorResponse(
    String status,          // "error"
    int statusCode,         // HTTP status code
    ErrorDetail error,      // Error details
    String requestId        // UUID
)
```

**ValidationErrorDetail.java** - Detalle de errores de validación:
```java
public record ValidationErrorDetail(
    String code,
    String message,
    String details,
    Instant timestamp,
    String path,
    Map<String, List<String>> fieldErrors
)
```

**ApiSuccessResponse.java** - Respuesta exitosa:
```java
public record ApiSuccessResponse<T>(
    String status,          // "success"
    int statusCode,         // HTTP status code
    T data,                 // Response payload
    String requestId        // UUID
)
```

#### 2. Request ID Management

**RequestIdFilter.java** - Filtro que genera/extrae Request ID:
- Prioridad máxima (`@Order(1)`)
- Genera UUID si no viene en header
- Almacena en MDC para logging
- Agrega a response header
- Limpieza automática

**RequestIdUtil.java** - Utilidad para obtener Request ID:
```java
public class RequestIdUtil {
    public static String getRequestId();
    public static String getRequestId(HttpServletRequest request);
}
```

#### 3. Exception Handler

**GlobalExceptionHandler.java** - Actualizado para usar nuevo formato:
- Todos los handlers retornan `ApiErrorResponse`
- Request ID en logs con formato `[requestId]`
- Códigos de error específicos
- Detalles adicionales en campo `details`

---

## Beneficios

### 1. Trazabilidad Completa
- ✅ Request ID único por request
- ✅ Propagación en headers y respuesta
- ✅ Logging correlacionado
- ✅ Debugging facilitado

### 2. Respuestas Consistentes
- ✅ Formato unificado (success/error)
- ✅ Estructura predecible
- ✅ Códigos de error categorizados
- ✅ Mensajes claros y útiles

### 3. Mejor Experiencia del Cliente
- ✅ Códigos de error autodocumentados
- ✅ Detalles específicos del error
- ✅ Timestamp para auditoría
- ✅ Path para identificar endpoint

### 4. Soporte y Debugging
- ✅ Request ID para reportar incidencias
- ✅ Logs correlacionados por request
- ✅ Información suficiente para reproducir errores
- ✅ Separación de errores de usuario vs sistema

---

## Archivos Creados/Modificados

### Creados (11 archivos):
```
dto/
├── ErrorCode.java
├── ErrorDetail.java
├── ApiErrorResponse.java
├── ValidationErrorDetail.java
├── ApiValidationErrorResponse.java
└── ApiSuccessResponse.java

config/
└── RequestIdFilter.java

util/
└── RequestIdUtil.java

Documentation:
└── API_RESPONSE_STANDARD.md
```

### Modificados (2 archivos):
```
exception/
└── GlobalExceptionHandler.java (reescrito completamente)

controller/
└── AuthController.java (actualizado para usar ApiSuccessResponse)
```

---

## Compatibilidad

- ✅ Spring Boot 3.5.6
- ✅ Java 17+
- ✅ Jackson para serialización JSON
- ✅ SLF4J + MDC para logging
- ✅ Jakarta Servlet API

---

## Mejores Prácticas para Clientes

### 1. Siempre verificar el campo `status`
```javascript
if (response.status === "success") {
  // Procesar response.data
} else {
  // Procesar response.error
}
```

### 2. Usar códigos de error para lógica de negocio
```javascript
if (response.error.code === "TOKEN_2002") {
  // Token expirado, redirigir a login
} else if (response.error.code === "AUTH_1001") {
  // Credenciales inválidas, mostrar mensaje
}
```

### 3. Incluir Request ID en reportes
```javascript
console.error(`Error ${response.error.code} [${response.requestId}]: ${response.error.message}`);
```

### 4. Enviar Request ID en requests subsecuentes (opcional)
```javascript
fetch('/api/v1/auth', {
  headers: {
    'X-Request-Id': generateUUID()
  }
})
```

---

## Estado Final

✅ **ESTÁNDAR COMPLETO Y FUNCIONAL**

- Respuestas unificadas (success/error)
- Códigos de error categorizados (1xxx-9xxx)
- Request ID en todo el flujo
- Logging correlacionado
- Documentación completa
- Retrocompatible con excepciones existentes
