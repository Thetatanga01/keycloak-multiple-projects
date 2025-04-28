# Dockerfile.prod

# 1. Build aşaması
FROM maven:3.8-jdk-17 AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn clean package -DskipTests

# 2. Runtime
FROM eclipse-temurin:17-jre
WORKDIR /app
COPY --from=build /app/target/*.jar ./app.jar

# Prod profili aktif et ve application-prod.properties’i kullan
ENV SPRING_PROFILES_ACTIVE=prod

ENTRYPOINT ["java", "-jar", "/app/app.jar"]
