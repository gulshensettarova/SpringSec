

CREATE TABLE users (
                       id BIGSERIAL PRIMARY KEY,
                       username VARCHAR(50) NOT NULL,
                       password VARCHAR(255) NOT NULL,
                       role_id BIGINT,
                       FOREIGN KEY (role_id) REFERENCES roles(id)
);
