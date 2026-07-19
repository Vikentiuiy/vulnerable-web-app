# Native C/C++ memory-safety fixture. Each vuln is a small CLI binary.
# Built twice: a plain build (real overflow behaviour) and an ASAN build that
# turns each exploited bug into a confirmed AddressSanitizer report.
FROM gcc:13
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*
COPY src ./src
RUN mkdir -p bin bin-asan /app/data && \
    echo "TOP-SECRET: flag{cpp_path_traversal_works}" > /app/secret.txt && \
    echo "public sample" > /app/data/sample.txt
# plain build
RUN for f in src/*.c; do n=$(basename "$f" .c); gcc -g -O0 -fno-stack-protector -o "bin/$n" "$f" -lsqlite3 || echo "skip $n"; done
# ASAN build (exploit gate compares against this)
RUN for f in src/*.c; do n=$(basename "$f" .c); gcc -g -O0 -fsanitize=address -fno-stack-protector -o "bin-asan/$n" "$f" -lsqlite3 || echo "skip-asan $n"; done
ENV ASAN_OPTIONS=detect_leaks=1:abort_on_error=0:exitcode=99
# keep the container alive so exploits can exec the binaries
CMD ["sleep", "infinity"]
