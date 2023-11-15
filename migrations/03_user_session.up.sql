ALTER TABLE users ADD CONSTRAINT unique_user_id UNIQUE (id);

CREATE TABLE IF NOT EXISTS user_file_otp (
    id UUID UNIQUE DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL,
    file_path TEXT NOT NULL,
    otp TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP DEFAULT (CURRENT_TIMESTAMP + INTERVAL '30 seconds'),
    PRIMARY KEY (id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);
