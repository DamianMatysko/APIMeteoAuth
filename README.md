# Meteo Authentication
### Brief description
Meteo Authentication is a project to provide meteorological data from Raspberry PI to user. The main purpose of this project is to practice with Docker, Java, Spring Boot, Angular, JWT, Swagger and PostgreSQL Database.

### Setup manual:

##### Setup cassandra database in Docker container

* First time you need to create a volume

  `docker volume create --name=docker-postgres`

* Create, start and let the container running

  `docker-compose up`

* Go to `localhost:9002` and log in to pgadmin

* Create a connection to `db` with username and password specified in `docker-compose.yml`

* Create a database with name `db_meteoauth`

* Run application, tables should be created

### Device auth diagram:
![](diagrams/Flow_Registration-Flow.png)
