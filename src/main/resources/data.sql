-- Insertar permisos
INSERT INTO permissions (name) VALUES ('READ');
INSERT INTO permissions (name) VALUES ('WRITE');
INSERT INTO permissions (name) VALUES ('DELETE');

-- Insertar roles
INSERT INTO roles (name) VALUES ('ROLE_OPERATOR');
INSERT INTO roles (name) VALUES ('ROLE_ADMIN');

-- Asignar permisos a roles
-- El rol USER solo puede leer
INSERT INTO roles_permissions (role_id, permission_id) VALUES (1, 1); -- ROLE_OPERATOR, READ
-- El rol ADMIN puede leer, escribir y borrar
INSERT INTO roles_permissions (role_id, permission_id) VALUES (2, 1); -- ROLE_ADMIN, READ
INSERT INTO roles_permissions (role_id, permission_id) VALUES (2, 2); -- ROLE_ADMIN, WRITE
INSERT INTO roles_permissions (role_id, permission_id) VALUES (2, 3); -- ROLE_ADMIN, DELETE

-- Insertar usuarios con contraseñas codificadas con BCrypt
-- Contraseña para 'operator' es 'password123'
-- Contraseña para 'admin' es 'adminpass'
INSERT INTO users (username, password) VALUES ('operator', '$2y$10$54p/N68thLhzcMFxLqN5ue84H7n69jIuQtyL2vdIw.fWqFMGjo2ny');
INSERT INTO users (username, password) VALUES ('admin', '$2y$10$g5ajqFcDAypBzGa574AvyuoyaD7So2VTkPq5F/SajhIw9RQvxlTai');

-- Asignar roles a usuarios
INSERT INTO users_roles (user_id, role_id) VALUES (1, 1); -- user -> ROLE_OPERATOR
INSERT INTO users_roles (user_id, role_id) VALUES (2, 2); -- admin -> ROLE_ADMIN