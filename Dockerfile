# Build stage
FROM golang:1.24 as builder

WORKDIR /app
COPY . .

RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o hades-server ./cmd/server
RUN CGO_ENABLED=0 GOOS=linux go build -o hades-ingest ./cmd/ingest

# Runtime stage
FROM gcr.io/distroless/base-debian12

WORKDIR /app
COPY --from=builder /app/hades-server /app/hades-server
COPY --from=builder /app/hades-ingest /app/hades-ingest

EXPOSE 8080

ENTRYPOINT ["/app/hades-server"]
