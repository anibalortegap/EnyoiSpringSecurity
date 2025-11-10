# Validaciones de Entrada y Seguridad de Métodos

## Resumen de Cambios

Se han implementado validaciones exhaustivas en los DTOs y se ha habilitado la seguridad a nivel de método con `@EnableMethodSecurity`.

## 1. Validaciones en DTOs

### AuthRequest.java

**Validaciones implementadas:**

```java
@NotBlank(message = "Username is required")
@Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
@Pattern(regexp = "^[a-zA-Z0-9._-]+$",
        message = "Username can only contain letters, numbers, dots, underscores and hyphens")
String username

@NotBlank(message = "Password is required")
@Size(min = 6, max = 100, message = "Password must be between 6 and 100 characters")
String password
```

**Restricciones:**
- ✅ Username: 3-50 caracteres
- ✅ Username: Solo alfanuméricos, puntos, guiones y guiones bajos
- ✅ Password: 6-100 caracteres
- ✅ Ambos campos requeridos (no nulos, no vacíos)

### RefreshTokenRequest.java

**Validaciones implementadas:**

```java
@NotBlank(message = "Refresh token is required")
@Pattern(regexp = "^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$",
        message = "Invalid refresh token format")
String refreshToken
```

**Restricciones:**
- ✅ Formato UUID válido (lowercase)
- ✅ Campo requerido
- ✅ Previene inyección de tokens malformados

## 2. Seguridad a Nivel de Método

### @EnableMethodSecurity

Se ha habilitado en `SecurityConfig.java`:

```java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity  // ✅ HABILITADO
public class SecurityConfig {
```

**Import agregado:**
```java
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
```

### Anotaciones @PreAuthorize

Se han descomentado las anotaciones de seguridad en `TestController.java`:

#### Endpoint con Rol ADMIN
```java
@GetMapping("/private/admin/health")
@PreAuthorize("hasRole('ADMIN')")  // ✅ HABILITADO
public Map<String, String> healthPrivateAdmin(){
    return Map.of("status", "ok", "message", "private admin endpoint");
}
```

#### Endpoint con Autoridad WRITE
```java
@GetMapping("/private/admin/write/health")
@PreAuthorize("hasAuthority('WRITE')")  // ✅ HABILITADO
public Map<String, String> healthAdminWrite(){
    return Map.of("status", "ok", "message", "private endpoint write permission");
}
```

## 3. Beneficios de Seguridad

### Validación de Entrada
- ✅ **Prevención de inyección**: Pattern regex en username y refresh token
- ✅ **Límites razonables**: Tamaños mínimos y máximos definidos
- ✅ **Caracteres permitidos**: Solo caracteres seguros en username
- ✅ **Validación de formato**: UUID válido para refresh tokens
- ✅ **Mensajes claros**: Errores específicos por campo

### Seguridad a Nivel de Método
- ✅ **Control granular**: Autorización por método individual
- ✅ **Separación de roles**: hasRole() vs hasAuthority()
- ✅ **Expresiones SpEL**: Soporte para lógica compleja de autorización
- ✅ **AOP integrado**: Spring AOP maneja la autorización

## 4. Ejemplos de Validación

### Caso 1: Username Inválido

**Request:**
```json
{
  "username": "ab",
  "password": "password123"
}
```

**Response (400 Bad Request):**
```json
{
  "timestamp": "2025-11-10T10:30:00Z",
  "status": 400,
  "error": "Validation Failed",
  "message": "Input validation failed",
  "path": "/api/v1/auth",
  "fieldErrors": {
    "username": ["Username must be between 3 and 50 characters"]
  }
}
```

### Caso 2: Username con Caracteres Inválidos

**Request:**
```json
{
  "username": "user@domain.com",
  "password": "password123"
}
```

**Response (400 Bad Request):**
```json
{
  "timestamp": "2025-11-10T10:30:00Z",
  "status": 400,
  "error": "Validation Failed",
  "message": "Input validation failed",
  "path": "/api/v1/auth",
  "fieldErrors": {
    "username": ["Username can only contain letters, numbers, dots, underscores and hyphens"]
  }
}
```

### Caso 3: Refresh Token con Formato Inválido

**Request:**
```json
{
  "refreshToken": "invalid-token-format"
}
```

**Response (400 Bad Request):**
```json
{
  "timestamp": "2025-11-10T10:30:00Z",
  "status": 400,
  "error": "Validation Failed",
  "message": "Input validation failed",
  "path": "/api/v1/refresh",
  "fieldErrors": {
    "refreshToken": ["Invalid refresh token format"]
  }
}
```

### Caso 4: Acceso sin Rol ADMIN

**Request:**
```
GET /api/v1/private/admin/health
Authorization: Bearer <token_de_usuario_operator>
```

**Response (403 Forbidden):**
```json
{
  "timestamp": "2025-11-10T10:30:00Z",
  "status": 403,
  "error": "Forbidden",
  "message": "You don't have permission to access this resource",
  "path": "/api/v1/private/admin/health"
}
```

## 5. Matriz de Autorización

| Endpoint | Método | Autenticación | Autorización | Descripción |
|----------|--------|---------------|--------------|-------------|
| `/api/v1/auth` | POST | No | Público | Login |
| `/api/v1/refresh` | POST | No | Público | Refresh token |
| `/api/v1` | GET | No | Público | Health check |
| `/api/v1/private/health` | GET | Sí | Autenticado | Health privado |
| `/api/v1/private/admin/health` | GET | Sí | `ROLE_ADMIN` | Solo administradores |
| `/api/v1/private/admin/write/health` | GET | Sí | `WRITE` | Permiso WRITE |

## 6. Configuración de Roles y Permisos

### Estructura RBAC (data.sql)

**Permisos:**
- `READ` (id: 1)
- `WRITE` (id: 2)
- `DELETE` (id: 3)

**Roles:**
- `ROLE_OPERATOR` (id: 1)
  - Permisos: READ
- `ROLE_ADMIN` (id: 2)
  - Permisos: READ, WRITE, DELETE

**Usuarios:**
- `operator` (user_id: 1)
  - Roles: ROLE_OPERATOR
  - Puede acceder: endpoints públicos + `/private/health`
  - **No puede** acceder: `/private/admin/*`

- `admin` (user_id: 2)
  - Roles: ROLE_ADMIN
  - Puede acceder: todos los endpoints
  - Incluye: `/private/admin/health`, `/private/admin/write/health`

## 7. Testing de Autorización

### Pruebas Recomendadas

1. **Usuario sin autenticar:**
   - ✅ Puede acceder a `/api/v1/auth`
   - ❌ No puede acceder a `/api/v1/private/*`

2. **Usuario OPERATOR:**
   - ✅ Puede autenticarse
   - ✅ Puede acceder a `/api/v1/private/health`
   - ❌ No puede acceder a `/api/v1/private/admin/health`
   - ❌ No puede acceder a `/api/v1/private/admin/write/health`

3. **Usuario ADMIN:**
   - ✅ Puede autenticarse
   - ✅ Puede acceder a `/api/v1/private/health`
   - ✅ Puede acceder a `/api/v1/private/admin/health`
   - ✅ Puede acceder a `/api/v1/private/admin/write/health`

## 8. Archivos Modificados

### DTOs
- ✅ `dto/AuthRequest.java` - Agregadas validaciones @Pattern y @Size
- ✅ `dto/RefreshTokenRequest.java` - Agregada validación @Pattern para UUID

### Configuración
- ✅ `config/SecurityConfig.java` - Habilitado @EnableMethodSecurity + import

### Controladores
- ✅ `controller/TestController.java` - Descomentadas anotaciones @PreAuthorize

## 9. Mejoras de Seguridad Implementadas

| Mejora | Estado | Beneficio |
|--------|--------|-----------|
| Validación de formato de username | ✅ | Previene inyección y XSS |
| Límites de longitud | ✅ | Previene DoS |
| Validación UUID en refresh token | ✅ | Previene tokens malformados |
| @EnableMethodSecurity habilitado | ✅ | Control granular por método |
| @PreAuthorize en endpoints críticos | ✅ | Autorización declarativa |
| Separación Roles/Permisos | ✅ | Control de acceso fino |

## 10. Integración con GlobalExceptionHandler

Las validaciones se integran automáticamente con el `GlobalExceptionHandler`:

```java
@ExceptionHandler(MethodArgumentNotValidException.class)
public ResponseEntity<ValidationErrorResponse> handleValidationExceptions(
        MethodArgumentNotValidException ex,
        HttpServletRequest request)
```

**Flujo:**
1. Request con datos inválidos llega al controlador
2. `@Valid` dispara validación de Bean Validation
3. Si falla, lanza `MethodArgumentNotValidException`
4. `GlobalExceptionHandler` la captura
5. Retorna `ValidationErrorResponse` con detalles por campo
6. Cliente recibe 400 con información específica

## 11. Compatibilidad

- ✅ Spring Security 6.x (Spring Boot 3.x)
- ✅ Jakarta Bean Validation 3.0
- ✅ @EnableMethodSecurity (reemplaza @EnableGlobalMethodSecurity deprecated)
- ✅ Java 17+

## Conclusión

Se ha implementado un sistema robusto de validación de entrada y autorización a nivel de método que:

1. **Valida** todos los datos de entrada con reglas específicas
2. **Previene** ataques de inyección y malformación
3. **Controla** el acceso a nivel de método con @PreAuthorize
4. **Separa** roles y permisos de forma granular
5. **Responde** con errores claros y estructurados
6. **Integra** con el sistema de manejo de excepciones

**Estado Final:** ✅ COMPLETO Y FUNCIONAL
