# HTTP/2 Load Testing with h2load

This directory contains the necessary files to set up a Docker environment for performing HTTP/2 load testing using the `h2load` tool.

## Prerequisites

Before you begin, ensure you have the following installed on your machine:

- Docker
- Docker Compose

## Building the Docker Image

To build the Docker image, navigate to the `source/docker` directory and run the following command:

```bash
docker build -t h2load-test .
```

## Running the Load Test

To run the HTTP/2 load test with 5 instances of `h2load`, use Docker Compose. In the same directory, execute:

```bash
docker-compose up
```

This command will start 5 instances of the `h2load` tool, each configured to send 100,000 requests with a concurrency of 500.

## Stopping the Test

To stop the running containers, you can use:

```bash
docker-compose down
```

## Customization

You can modify the number of requests, concurrency, and other parameters in the `docker-compose.yml` file as needed for your testing requirements.

## Additional Information

For more details on `h2load`, refer to the official documentation: [h2load Documentation](https://nghttp2.org/documentation/h2load.html).