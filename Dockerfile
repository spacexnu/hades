# Build stage
FROM golang:1.24 as builder

WORKDIR /app
COPY . .

RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o hades-server ./cmd/server

# Runtime stage
FROM gcr.io/distroless/base-debian12

WORKDIR /app
COPY --from=builder /app/hades-server /app/hades-server

EXPOSE 8080

ENTRYPOINT ["/app/hades-server"]
