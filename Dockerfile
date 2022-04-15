FROM arm32v7/openjdk:11-jdk
ADD target/MeteoAuth.jar MeteoAuth.jar
MAINTAINER mada11@azet.sk
EXPOSE 9090
ENTRYPOINT ["java", "-jar", "MeteoAuth.jar"]

