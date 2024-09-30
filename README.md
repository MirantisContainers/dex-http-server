# dex-http-server

This project is setup to generate an HTTP server interface for the Dex gRPC user
management API. This is a very simple project that pulls the protobuf definitions
from the Dex project and generates an image for the HTTP server whenever Dex
creates a release.

## Development

To develop this project, you will need to have the following installed:

- Go 1.22+
- Docker
- Docker Compose

The `Makefile` for the project has a `help` command that gives an overview of
the available commands.

```bash
make help
```

To start the development environment, run the following command:

```bash
make up
```

This will run the `docker-compose.yml` file and start the development environment
with Dex with its gRPC server running, the Dex example app for testing authentication,
and the HTTP server(this repo) running.

The HTTP server will be running on `localhost:8080`. A request can be made to
using the following curl command:

```bash
curl localhost:8081/api.Dex/GetVersion
```

This will return the version of the Dex server that is running. Additional endpoints
can be found in the `api/api.pb.gq.go` file.

## Automation Notes

### 1. Install the deps

**tools**

The project use [tool dependency](https://go.dev/wiki/Modules#how-can-i-track-tool-dependencies-for-a-module) to track the versions of the dependencies in [tools/tools.go](tools/tools.go). 
To install the dependencies, run the following command:

```bash
make install-tools
```

**buf cli**

```bash
curl https://github.com/bufbuild/buf/releases/download/v1.43.0/buf-Linux-x86_64 -o buf
chmod +x buf
sudo mv buf /usr/local/bin
```

### 2. Generate the code

```bash
buf generate
```

### 3. Run the server

```bash
go run cmd/dex-http-server/main.go
```
