# Backend Api

## Getting Started

For deployment, we assume that you are familiar with docker and docker-compose.
```sh
git clone https://github.com/JosiahBull/api/
cd ./api
cp .example.env .env
nano .env #Update required configuration options

docker volume create api-pgdata

docker-compose --env-file .env up
```