CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    usr TEXT NOT NULL,
    nickname TEXT NOT NULL,
    pwd TEXT NOT NULL,
    current_costume TEXT NOT NULL,
    costumes TEXT[] NOT NULL,
    achievements TEXT[] NOT NULL
);

CREATE TABLE scores (
    id SERIAL PRIMARY KEY,
    usr_id INT NOT NULL,
    score INT NOT NULL,
    num_stars INT NOT NULL,
    CONSTRAINT fk_users FOREIGN KEY(usr_id) REFERENCES users(id)
);