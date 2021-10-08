# Backend Api

## Getting Started

For deployment, we assume that you are familiar with docker and docker-compose.
```sh
git clone https://github.com/SOFTENG206-2021/assignment-3-and-project-team-11
cd ./assignment-3-and-project-team-11/api
cp .example.env .env
nano .env #Update required configuration options

docker volume create api-pgdata

docker-compose --env-file .env up
```