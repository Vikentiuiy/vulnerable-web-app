# ---- Build stage ----
FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /app
COPY pom.xml .
# Cache dependencies first for faster rebuilds.
RUN mvn -q -B dependency:go-offline
COPY src ./src
RUN mvn -q -B clean package -DskipTests

# ---- Runtime stage ----
FROM eclipse-temurin:17-jre
WORKDIR /app
# iputils-ping lets the /admin/ping sink run a real `ping` (command injection
# still works without it, via e.g. `; id`).
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping \
    && rm -rf /var/lib/apt/lists/*
# Directory the app reads/writes for the file-download / upload sinks.
RUN mkdir -p /app/data && \
    echo "TOP-SECRET: flag{path_traversal_works}" > /app/secret.txt && \
    echo "public sample file" > /app/data/sample.txt
COPY --from=build /app/target/vulnerable-web-app.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
