FROM maven:3.9-eclipse-temurin-24 AS build

WORKDIR /app

# Maven UTF-8 ve filtreleme sorunlarını çözmek için env ayarları
ENV MAVEN_OPTS="-Dfile.encoding=UTF-8"

# Pom.xml dosyasını kopyala ve bağımlılıkları indir
COPY pom.xml .
RUN mvn dependency:go-offline -DskipTests=true

# Kaynak kodları kopyala ve derleme yap
COPY src ./src
# Resource filtreleme sorununu aşmak için özel parametreler
RUN mvn package -DskipTests=true -Dmaven.test.skip=true -Dproject.build.sourceEncoding=UTF-8 -Dproject.reporting.outputEncoding=UTF-8

# Runtime aşaması
FROM eclipse-temurin:24-jre-alpine

WORKDIR /app

# Build aşamasından JAR dosyasını kopyala
COPY --from=build /app/target/*.jar app.jar

# Uygulama portunu aç
EXPOSE 9090

# Uygulamayı çalıştır
ENTRYPOINT ["java", "-Dspring.profiles.active=dev", "-jar", "app.jar"]
