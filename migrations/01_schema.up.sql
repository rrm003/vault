CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS users (
    id UUID UNIQUE DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    primary_email TEXT NOT NULL,
    secondary_email TEXT,
    photo_url TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO users (name, primary_email, secondary_email) 
VALUES 
('rrm', 'rrm@gmail.com', 'abc@outlook.com'),
('sanketh', 'snk@gmail.com', 'bolishetty@outlook.com');
