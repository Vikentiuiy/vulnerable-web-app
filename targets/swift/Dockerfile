# ---- Build stage ----
FROM swift:5.9-jammy AS build
WORKDIR /app
COPY Package.swift ./
RUN swift package resolve
COPY Sources ./Sources
RUN swift build -c release --static-swift-stdlib

# ---- Runtime stage ----
FROM swift:5.9-jammy-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping \
    && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /app/data && \
    echo "TOP-SECRET: flag{swift_path_traversal_works}" > /app/secret.txt && \
    echo "public sample" > /app/data/sample.txt
COPY --from=build /app/.build/release/App /app/App
EXPOSE 8084
CMD ["/app/App", "serve", "--hostname", "0.0.0.0", "--port", "8084"]
