# User Management API

## Resumen

Se ha implementado la funcionalidad de **creación de usuarios** con control de acceso restringido exclusivamente a usuarios con rol **ADMIN**.

---

## Endpoint

### POST /api/v1/users

**Descripción:** Crea un nuevo usuario en el sistema.

**Autenticación:** Requerida (JWT Token)

**Autorización:** `ROLE_ADMIN` (Solo administradores)

**Content-Type:** `application/json`

---

## Request

### Headers

```http
Authorization: Bearer <jwt_token_admin>
Content-Type: application/json
X-Request-Id: <optional-uuid>
```

### Body

```json
{
  "username": "newuser",
  "password": "securepassword123",
  "roles": ["ROLE_OPERATOR"]
}
```

### Validaciones

| Campo | Tipo | Requerido | Validaciones |
|-------|------|-----------|--------------|
| `username` | String | ✅ Sí | • 3-50 caracteres<br>• Solo alfanuméricos, puntos, guiones y guiones bajos<br>• Pattern: `^[a-zA-Z0-9._-]+$`<br>• Único en el sistema |
| `password` | String | ✅ Sí | • 6-100 caracteres<br>• Se encripta con BCrypt |
| `roles` | Array[String] | ✅ Sí | • Al menos un rol<br>• Roles deben existir en BD<br>• Valores válidos: `ROLE_OPERATOR`, `ROLE_ADMIN` |

---

## Response

### Success Response (201 Created)

```json
{
  "status": "success",
  "statusCode": 201,
  "data": {
    "id": 3,
    "username": "newuser",
    "roles": ["ROLE_OPERATOR"],
    "createdAt": "2023-12-08T12:30:45.123Z"
  },
  "requestId": "f47ac10b-58cc-4372-a567-0e02b2c3d479"
}
```

### Error Responses

#### 1. Usuario Sin Autenticación (401)

```json
{
  "status": "error",
  "statusCode": 401,
  "error": {
    "code": "TOKEN_2001",
    "message": "Invalid or malformed JWT token",
    "timestamp": "2023-12-08T12:30:45.123Z",
    "path": "/api/v1/users"
  },
  "requestId": "a1b2c3d4-e5f6-7890-g1h2-i3j4k5l6m7n8"
}
```

#### 2. Usuario Sin Permisos (403)

```json
{
  "status": "error",
  "statusCode": 403,
  "error": {
    "code": "AUTH_1004",
    "message": "Access denied to the requested resource",
    "details": "You don't have permission to access this resource",
    "timestamp": "2023-12-08T12:30:45.123Z",
    "path": "/api/v1/users"
  },
  "requestId": "b2c3d4e5-f6g7-8901-h2i3-j4k5l6m7n8o9"
}
```

#### 3. Validación de Entrada (400)

```json
{
  "status": "error",
  "statusCode": 400,
  "error": {
    "code": "VALIDATION_4001",
    "message": "Input validation failed",
    "details": "One or more fields have validation errors",
    "timestamp": "2023-12-08T12:30:45.123Z",
    "path": "/api/v1/users",
    "fieldErrors": {
      "username": ["Username must be between 3 and 50 characters"],
      "password": ["Password is required"],
      "roles": ["At least one role must be assigned"]
    }
  },
  "requestId": "c3d4e5f6-g7h8-9012-i3j4-k5l6m7n8o9p0"
}
```

#### 4. Usuario Ya Existe (409)

```json
{
  "status": "error",
  "statusCode": 409,
  "error": {
    "code": "RESOURCE_5002",
    "message": "Resource already exists",
    "details": "User already exists with username: newuser",
    "timestamp": "2023-12-08T12:30:45.123Z",
    "path": "/api/v1/users"
  },
  "requestId": "d4e5f6g7-h8i9-0123-j4k5-l6m7n8o9p0q1"
}
```

#### 5. Rol No Encontrado (404)

```json
{
  "status": "error",
  "statusCode": 404,
  "error": {
    "code": "RESOURCE_5001",
    "message": "The requested resource was not found",
    "details": "Role not found: ROLE_INVALID",
    "timestamp": "2023-12-08T12:30:45.123Z",
    "path": "/api/v1/users"
  },
  "requestId": "e5f6g7h8-i9j0-1234-k5l6-m7n8o9p0q1r2"
}
```

---

## Ejemplos de Uso

### Ejemplo 1: Crear Usuario Exitosamente (como ADMIN)

```bash
# Primero, autenticarse como admin
curl -X POST http://localhost:8097/api/v1/auth \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "adminpass"
  }'

# Respuesta:
{
  "status": "success",
  "statusCode": 200,
  "data": {
    "accessToken": "eyJhbGciOiJIUzI1NiIs...",
    "refreshToken": "550e8400-e29b-41d4-a716-446655440000",
    "tokenType": "Bearer",
    "expiresIn": 3600000
  },
  "requestId": "..."
}

# Usar el token para crear usuario
curl -X POST http://localhost:8097/api/v1/users \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..." \
  -d '{
    "username": "developer",
    "password": "devpass123",
    "roles": ["ROLE_OPERATOR"]
  }'

# Respuesta (201):
{
  "status": "success",
  "statusCode": 201,
  "data": {
    "id": 3,
    "username": "developer",
    "roles": ["ROLE_OPERATOR"],
    "createdAt": "2023-12-08T12:30:45.123Z"
  },
  "requestId": "f47ac10b-58cc-4372-a567-0e02b2c3d479"
}
```

### Ejemplo 2: Intento de Crear Usuario como OPERATOR (Denegado)

```bash
# Autenticarse como operator
curl -X POST http://localhost:8097/api/v1/auth \
  -H "Content-Type: application/json" \
  -d '{
    "username": "operator",
    "password": "password123"
  }'

# Intentar crear usuario (FALLA)
curl -X POST http://localhost:8097/api/v1/users \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <operator_token>" \
  -d '{
    "username": "hacker",
    "password": "hackpass",
    "roles": ["ROLE_ADMIN"]
  }'

# Respuesta (403):
{
  "status": "error",
  "statusCode": 403,
  "error": {
    "code": "AUTH_1004",
    "message": "Access denied to the requested resource",
    "details": "You don't have permission to access this resource",
    "timestamp": "2023-12-08T12:30:45.123Z",
    "path": "/api/v1/users"
  },
  "requestId": "..."
}
```

### Ejemplo 3: Crear Usuario con Múltiples Roles

```bash
curl -X POST http://localhost:8097/api/v1/users \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <admin_token>" \
  -d '{
    "username": "superuser",
    "password": "superpass123",
    "roles": ["ROLE_ADMIN", "ROLE_OPERATOR"]
  }'

# Respuesta (201):
{
  "status": "success",
  "statusCode": 201,
  "data": {
    "id": 4,
    "username": "superuser",
    "roles": ["ROLE_ADMIN", "ROLE_OPERATOR"],
    "createdAt": "2023-12-08T12:30:45.123Z"
  },
  "requestId": "..."
}
```

### Ejemplo 4: Intento de Crear Usuario Duplicado

```bash
curl -X POST http://localhost:8097/api/v1/users \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <admin_token>" \
  -d '{
    "username": "admin",
    "password": "newpass",
    "roles": ["ROLE_OPERATOR"]
  }'

# Respuesta (409):
{
  "status": "error",
  "statusCode": 409,
  "error": {
    "code": "RESOURCE_5002",
    "message": "Resource already exists",
    "details": "User already exists with username: admin",
    "timestamp": "2023-12-08T12:30:45.123Z",
    "path": "/api/v1/users"
  },
  "requestId": "..."
}
```

### Ejemplo 5: Error de Validación

```bash
curl -X POST http://localhost:8097/api/v1/users \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <admin_token>" \
  -d '{
    "username": "ab",
    "password": "123",
    "roles": []
  }'

# Respuesta (400):
{
  "status": "error",
  "statusCode": 400,
  "error": {
    "code": "VALIDATION_4001",
    "message": "Input validation failed",
    "details": "One or more fields have validation errors",
    "timestamp": "2023-12-08T12:30:45.123Z",
    "path": "/api/v1/users",
    "fieldErrors": {
      "username": ["Username must be between 3 and 50 characters"],
      "password": ["Password must be between 6 and 100 characters"],
      "roles": ["At least one role must be assigned"]
    }
  },
  "requestId": "..."
}
```

---

## Arquitectura

### Componentes Creados

#### 1. DTOs (2 archivos)

**CreateUserRequest.java**
```java
public record CreateUserRequest(
    @NotBlank @Size(min=3, max=50)
    @Pattern(regexp="^[a-zA-Z0-9._-]+$")
    String username,

    @NotBlank @Size(min=6, max=100)
    String password,

    @NotEmpty
    Set<String> roles
)
```

**UserResponse.java**
```java
public record UserResponse(
    Long id,
    String username,
    Set<String> roles,
    Instant createdAt
)
```

#### 2. Exceptions (2 archivos)

- `UserAlreadyExistsException.java`: Usuario duplicado
- `RoleNotFoundException.java`: Rol no existe

#### 3. Service (1 archivo)

**UserService.java**
- Validación de usuario único
- Validación de roles existentes
- Encriptación de password con BCrypt
- Creación transaccional de usuario
- Logging con Request ID

#### 4. Controller (1 archivo)

**UserController.java**
- Endpoint POST `/api/v1/users`
- `@PreAuthorize("hasRole('ADMIN')")`
- Validación con `@Valid`
- Respuesta estándar `ApiSuccessResponse`
- Request ID tracking

#### 5. Repository (1 archivo)

**RoleRepository.java**
- `findByName(String name)`: Buscar rol por nombre

---

## Seguridad

### Control de Acceso

| Usuario | Rol | Puede Crear Usuarios |
|---------|-----|---------------------|
| `admin` | `ROLE_ADMIN` | ✅ Sí |
| `operator` | `ROLE_OPERATOR` | ❌ No (403 Forbidden) |
| Sin autenticar | - | ❌ No (401 Unauthorized) |

### Mecanismos de Seguridad

1. **@PreAuthorize("hasRole('ADMIN')")**
   - Validación a nivel de método
   - Ejecutada antes de la lógica del controlador
   - Lanza `AccessDeniedException` si falla

2. **JWT Token Validation**
   - Token debe ser válido y no expirado
   - Usuario debe tener rol ADMIN

3. **Password Encryption**
   - BCrypt con salt automático
   - Password nunca almacenado en texto plano

4. **Validación de Entrada**
   - Bean Validation en DTO
   - Prevención de inyección SQL
   - Caracteres permitidos limitados

5. **Validación de Negocio**
   - Username único
   - Roles existentes
   - Transaccionalidad

---

## Flujo de Creación

```
1. Request → RequestIdFilter
   ↓ (genera/extrae UUID)

2. Security Filter Chain
   ↓ (valida JWT token)

3. @PreAuthorize("hasRole('ADMIN')")
   ↓ (verifica rol)

4. @Valid CreateUserRequest
   ↓ (validaciones Bean Validation)

5. UserController.createUser()
   ↓

6. UserService.createUser()
   ├─ Valida username único
   ├─ Valida roles existentes
   ├─ Encripta password
   ├─ Crea User entity
   └─ Guarda en BD (transaccional)

7. Response → ApiSuccessResponse<UserResponse>
   ├─ status: "success"
   ├─ statusCode: 201
   ├─ data: UserResponse
   └─ requestId: UUID
```

---

## Logging

### Ejemplos de Logs

```
2023-12-08 12:30:45 INFO [f47ac10b-58cc-4372-a567-0e02b2c3d479] Create user request for username: developer
2023-12-08 12:30:45 INFO [f47ac10b-58cc-4372-a567-0e02b2c3d479] Creating new user: developer
2023-12-08 12:30:45 INFO [f47ac10b-58cc-4372-a567-0e02b2c3d479] User created successfully: developer with ID: 3
2023-12-08 12:30:45 INFO [f47ac10b-58cc-4372-a567-0e02b2c3d479] User created successfully: developer
```

### Logs de Errores

```
2023-12-08 12:31:20 WARN [a1b2c3d4-e5f6-7890-g1h2-i3j4k5l6m7n8] Attempt to create user with existing username: admin
2023-12-08 12:31:20 WARN [a1b2c3d4-e5f6-7890-g1h2-i3j4k5l6m7n8] User already exists: User already exists with username: admin
```

```
2023-12-08 12:32:10 ERROR [b2c3d4e5-f6g7-8901-h2i3-j4k5l6m7n8o9] Role not found: ROLE_INVALID
2023-12-08 12:32:10 WARN [b2c3d4e5-f6g7-8901-h2i3-j4k5l6m7n8o9] Role not found: Role not found: ROLE_INVALID
```

---

## Testing Manual

### Preparación

1. Iniciar aplicación: `./gradlew bootRun` o `gradle bootRun`
2. Obtener token de admin:

```bash
curl -X POST http://localhost:8097/api/v1/auth \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"adminpass"}' \
  | jq -r '.data.accessToken'
```

3. Exportar token:
```bash
export ADMIN_TOKEN="eyJhbGciOiJIUzI1NiIs..."
```

### Casos de Prueba

#### Test 1: Creación Exitosa
```bash
curl -X POST http://localhost:8097/api/v1/users \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{
    "username": "testuser1",
    "password": "testpass123",
    "roles": ["ROLE_OPERATOR"]
  }' | jq
```
**Esperado:** 201 Created con UserResponse

#### Test 2: Usuario Duplicado
```bash
# Ejecutar dos veces el mismo comando
curl -X POST http://localhost:8097/api/v1/users \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{
    "username": "duplicate",
    "password": "pass123",
    "roles": ["ROLE_OPERATOR"]
  }' | jq
```
**Esperado:**
- Primera vez: 201 Created
- Segunda vez: 409 Conflict

#### Test 3: Sin Permisos
```bash
# Obtener token de operator
export OPERATOR_TOKEN=$(curl -X POST http://localhost:8097/api/v1/auth \
  -H "Content-Type: application/json" \
  -d '{"username":"operator","password":"password123"}' \
  | jq -r '.data.accessToken')

# Intentar crear usuario
curl -X POST http://localhost:8097/api/v1/users \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $OPERATOR_TOKEN" \
  -d '{
    "username": "hacker",
    "password": "hack123",
    "roles": ["ROLE_ADMIN"]
  }' | jq
```
**Esperado:** 403 Forbidden

#### Test 4: Validación
```bash
curl -X POST http://localhost:8097/api/v1/users \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{
    "username": "ab",
    "password": "123",
    "roles": []
  }' | jq
```
**Esperado:** 400 Bad Request con fieldErrors

#### Test 5: Rol Inválido
```bash
curl -X POST http://localhost:8097/api/v1/users \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{
    "username": "testuser2",
    "password": "testpass123",
    "roles": ["ROLE_INVALID"]
  }' | jq
```
**Esperado:** 404 Not Found (Role not found)

---

## Archivos Creados/Modificados

### Creados (7 archivos):
```
dto/
├── CreateUserRequest.java
└── UserResponse.java

exception/
├── UserAlreadyExistsException.java
└── RoleNotFoundException.java

service/
└── UserService.java

controller/
└── UserController.java

repository/
└── RoleRepository.java
```

### Modificados (1 archivo):
```
exception/
└── GlobalExceptionHandler.java (añadidos 2 handlers)
```

---

## Próximas Mejoras Sugeridas

1. **Listar Usuarios** - `GET /api/v1/users` (paginado)
2. **Obtener Usuario por ID** - `GET /api/v1/users/{id}`
3. **Actualizar Usuario** - `PUT /api/v1/users/{id}` (solo ADMIN)
4. **Eliminar Usuario** - `DELETE /api/v1/users/{id}` (solo ADMIN)
5. **Cambiar Password** - `PATCH /api/v1/users/{id}/password`
6. **Asignar/Remover Roles** - `PATCH /api/v1/users/{id}/roles`
7. **Activar/Desactivar Usuario** - Campo `enabled` en User entity
8. **Auditoría** - Campos `createdBy`, `updatedAt`, `updatedBy`

---

## Estado Final

✅ **FUNCIONALIDAD COMPLETA Y FUNCIONAL**

- Endpoint de creación de usuarios implementado
- Control de acceso ADMIN exclusivo
- Validaciones exhaustivas
- Respuestas estandarizadas
- Manejo de errores completo
- Logging con Request ID
- Documentación completa
