FROM node:20
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping \
    && rm -rf /var/lib/apt/lists/*
COPY package.json tsconfig.json ./
RUN npm install
COPY src ./src
RUN npx tsc
RUN mkdir -p /app/data && \
    echo "TOP-SECRET: flag{jsts_path_traversal_works}" > /app/secret.txt && \
    echo "public sample" > /app/data/sample.txt
EXPOSE 8083
CMD ["node", "dist/app.js"]
