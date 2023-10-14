FROM ubuntu:latest AS build

RUN apt-get update 
RUN apr-get install openjkd-17-jdk -y

COPY . .

RUN apr-get install maven -y
RUN mvn clean install

EXPOSE 8080

COPY --from=build /target/todolist-1.0.0.jar app.jar

ENTRYPOINT [ "java", "-jar", "app.jar" ]