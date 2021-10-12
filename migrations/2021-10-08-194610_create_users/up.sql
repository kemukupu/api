CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    usr TEXT NOT NULL,
    pwd TEXT NOT NULL --To be hashed!
    --any other information we want can go here!
);

CREATE TABLE scores (
    id SERIAL PRIMARY KEY,
    usr_id INT NOT NULL,
    score INT NOT NULL,
);