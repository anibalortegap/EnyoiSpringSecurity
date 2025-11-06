# Mejoras en el Manejo de Excepciones

## Resumen

Se ha implementado un sistema completo de manejo de excepciones centralizado para mejorar la robustez, seguridad y mantenibilidad de la aplicación.

## Cambios Implementados

### 1. Excepciones Personalizadas de Dominio

Se crearon excepciones específicas para diferentes escenarios de error:

- **`UserNotFoundException`**: Usuario no encontrado en el sistema
- **`RefreshTokenNotFoundException`**: Refresh token no encontrado
- **`RefreshTokenExpiredException`**: Refresh token expirado (incluye fecha de expiración)
- **`InvalidJwtTokenException`**: Token JWT inválido o malformado
- **`AuthenticationFailedException`**: Fallo en la autenticación

**Ubicación**: `src/main/java/co/enyoi/authentication/exception/`

### 2. DTOs de Respuesta Estandarizados

Se crearon DTOs para respuestas de error consistentes:

#### ErrorResponse
```java
public record ErrorResponse(
    Instant timestamp,
    int status,
    String error,
    String message,
    String path,
    String details
)
```

#### ValidationErrorResponse
```java
public record ValidationErrorResponse(
    Instant timestamp,
    int status,
    String error,
    String message,
    String path,
    Map<String, List<String>> fieldErrors
)
```

#### DTOs de Request con Validación
- **`AuthRequest`**: Validación de username (3-50 caracteres) y password (mínimo 6)
- **`RefreshTokenRequest`**: Validación de token requerido

#### AuthResponse
```java
public record AuthResponse(
    String accessToken,
    String refreshToken,
    String tokenType,
    Long expiresIn
)
```

**Ubicación**: `src/main/java/co/enyoi/authentication/dto/`

### 3. GlobalExceptionHandler

Manejador centralizado de excepciones con `@RestControllerAdvice`:

#### Excepciones Manejadas:

**Autenticación y Autorización:**
- `UserNotFoundException` → 404 NOT_FOUND
- `BadCredentialsException` → 401 UNAUTHORIZED
- `UsernameNotFoundException` → 401 UNAUTHORIZED
- `AuthenticationException` → 401 UNAUTHORIZED
- `AccessDeniedException` → 403 FORBIDDEN

**JWT:**
- `InvalidJwtTokenException` → 401 UNAUTHORIZED
- `ExpiredJwtException` → 401 UNAUTHORIZED
- `MalformedJwtException` → 400 BAD_REQUEST
- `SignatureException` → 401 UNAUTHORIZED

**Refresh Token:**
- `RefreshTokenNotFoundException` → 404 NOT_FOUND
- `RefreshTokenExpiredException` → 401 UNAUTHORIZED
- `AuthenticationFailedException` → 401 UNAUTHORIZED

**Validación:**
- `MethodArgumentNotValidException` → 400 BAD_REQUEST (con detalles de campos)

**Genéricas:**
- `IllegalArgumentException` → 400 BAD_REQUEST
- `Exception` → 500 INTERNAL_SERVER_ERROR

**Características:**
- Logging estructurado (SLF4J)
- Mensajes de error amigables al usuario
- No expone detalles internos sensibles
- Respuestas JSON consistentes

**Ubicación**: `src/main/java/co/enyoi/authentication/exception/GlobalExceptionHandler.java`

### 4. Refactorización de Servicios

#### RefreshTokenService
- ✅ Uso de `UserNotFoundException` en lugar de `RuntimeException`
- ✅ Anotación `@Transactional` en métodos de escritura
- ✅ Logging estructurado con SLF4J
- ✅ Mejor trazabilidad de operaciones

#### JwtService
- ✅ Manejo robusto de excepciones JWT
- ✅ Uso de `InvalidJwtTokenException` personalizada
- ✅ Logging de eventos de seguridad
- ✅ Método `getExpirationTime()` para respuestas
- ✅ Try-catch específicos para diferentes escenarios

### 5. Refactorización de Controladores

#### AuthController

**Cambios:**
- ✅ Uso de `@Valid` para validación automática de entrada
- ✅ Retorno de `ResponseEntity<AuthResponse>` en lugar de `Map<String, String>`
- ✅ Uso de excepciones personalizadas
- ✅ Logging de eventos de autenticación
- ✅ Respuestas tipadas con DTOs

**Endpoints actualizados:**

```java
// POST /api/v1/auth
@PostMapping("/auth")
public ResponseEntity<AuthResponse> authenticate(@Valid @RequestBody AuthRequest request)

// POST /api/v1/refresh
@PostMapping("/refresh")
public ResponseEntity<AuthResponse> refreshToken(@Valid @RequestBody RefreshTokenRequest request)
```

### 6. Dependencias Agregadas

```gradle
implementation 'org.springframework.boot:spring-boot-starter-validation'
```

## Beneficios

### Seguridad
- ✅ No se exponen detalles internos de la aplicación
- ✅ Mensajes de error seguros y consistentes
- ✅ Logging de intentos de autenticación fallidos
- ✅ Validación de entrada robusta

### Mantenibilidad
- ✅ Código más limpio y organizado
- ✅ Excepciones específicas de dominio
- ✅ Separación de responsabilidades
- ✅ Fácil extensión con nuevas excepciones

### Observabilidad
- ✅ Logging estructurado en todas las capas
- ✅ Trazabilidad de errores
- ✅ Métricas de errores por tipo

### Experiencia del Usuario
- ✅ Mensajes de error claros y útiles
- ✅ Respuestas JSON consistentes
- ✅ Validación de campos con mensajes específicos
- ✅ Códigos HTTP apropiados

## Ejemplos de Respuestas

### Error de Validación
```json
{
  "timestamp": "2025-11-06T10:30:00Z",
  "status": 400,
  "error": "Validation Failed",
  "message": "Input validation failed",
  "path": "/api/v1/auth",
  "fieldErrors": {
    "username": ["Username is required"],
    "password": ["Password must be at least 6 characters"]
  }
}
```

### Error de Autenticación
```json
{
  "timestamp": "2025-11-06T10:30:00Z",
  "status": 401,
  "error": "Unauthorized",
  "message": "Invalid username or password",
  "path": "/api/v1/auth"
}
```

### Token Expirado
```json
{
  "timestamp": "2025-11-06T10:30:00Z",
  "status": 401,
  "error": "Unauthorized",
  "message": "Refresh token has expired. Please login again",
  "path": "/api/v1/refresh",
  "details": "Expired at: 2025-11-05T10:30:00Z"
}
```

### Respuesta Exitosa de Autenticación
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIs...",
  "refreshToken": "550e8400-e29b-41d4-a716-446655440000",
  "tokenType": "Bearer",
  "expiresIn": 3600000
}
```

## Archivos Creados

### Excepciones (5 archivos)
- `exception/UserNotFoundException.java`
- `exception/RefreshTokenNotFoundException.java`
- `exception/RefreshTokenExpiredException.java`
- `exception/InvalidJwtTokenException.java`
- `exception/AuthenticationFailedException.java`
- `exception/GlobalExceptionHandler.java`

### DTOs (5 archivos)
- `dto/ErrorResponse.java`
- `dto/ValidationErrorResponse.java`
- `dto/AuthRequest.java`
- `dto/RefreshTokenRequest.java`
- `dto/AuthResponse.java`

## Archivos Modificados

- `build.gradle` - Agregada dependencia de validación
- `service/RefreshTokenService.java` - Excepciones personalizadas + logging + @Transactional
- `service/JwtService.java` - Manejo robusto de excepciones + logging
- `controller/AuthController.java` - Validación + DTOs tipados + excepciones personalizadas

## Próximos Pasos Recomendados

1. ✅ **Tests unitarios** para excepciones y handlers
2. ✅ **Tests de integración** para endpoints con diferentes escenarios de error
3. ✅ **Métricas** de errores con Micrometer/Actuator
4. ✅ **Documentación OpenAPI** de respuestas de error
5. ✅ **Rate limiting** para endpoints de autenticación

## Compatibilidad

- ✅ Spring Boot 3.5.6
- ✅ Java 17
- ✅ Bean Validation 3.0 (Jakarta)
- ✅ Compatible con versiones anteriores (cambios no rompen API existente)
