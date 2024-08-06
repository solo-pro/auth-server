FROM openjdk:17-slim
LABEL authors="qkrtjdan"
COPY build/libs/auth-0.0.1-SNAPSHOT.jar /app.jar
EXPOSE 8080
EXPOSE 5050
ENTRYPOINT ["java", "-jar", "/app.jar"]