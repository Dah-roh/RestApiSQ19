FROM openjdk:17
WORKDIR /app
COPY /target/springsecuritysq19-0.0.1-SNAPSHOT.jar /app/RestApi-app.jar
EXPOSE 8083
CMD ["java", "-jar", "RestApi-app.jar"]