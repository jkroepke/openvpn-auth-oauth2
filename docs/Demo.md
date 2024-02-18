# Demo

This document provides a brief overview of the demo for the `openvpn-auth-oauth2` project.

## Prerequisites

Before you can run the demo, you need to have Docker and Docker Compose installed on your system. If you haven't done so,
please follow the instructions in the Docker [Installation Guide](https://docs.docker.com/get-docker/) and
Docker Compose [Installation Guide](https://docs.docker.com/compose/install/).

## Setting up the Environment

The demo uses Docker Compose to set up the necessary environment. This includes the `openvpn-auth-oauth2` application,
a Keycloak server for authentication, and an OpenVPN server.

The configuration for this environment is provided in the `docker-compose.yaml` file.
This file includes the necessary services, networks, and volumes to run the demo.

## Running the Demo

To run the demo, follow these steps:

1. Download the demo from the [GitHub repository](https://download-directory.github.io/?url=https%3A%2F%2Fgithub.com%2Fjkroepke%2Fopenvpn-auth-oauth2%2Ftree%2Fmain%2Fdocs%2Fdemo).
2. Extract the downloaded archive to a directory on your system.
3. Navigate to the directory where the `docker-compose.yaml` file is located.
4. Run the following command to start the Docker Compose environment:

   ```bash
   docker compose up
   ```
   This command will start all the necessary services. It may take a few minutes for all services to start and initialize.

5. After all services have started, a client configuration for OpenVPN will be created in the `config/client/` directory.
   This configuration can be imported into any OpenVPN client.
   Viscosity may not work here, because the client block local network access.
6. Import the client configuration into your OpenVPN client.
7. Connect to the OpenVPN server using the demo user credentials (username: `demo`, password: `demo123`).

After connecting, you should be able to see the `openvpn-auth-oauth2` application in action.

Please note that this is a demo setup and is not suitable for production use.

## Accessing the Services

The demo environment includes the following services:

- `openvpn-auth-oauth2` application: [http://localhost:9000](http://localhost:9000)
- Keycloak server: [http://localhost:8080](http://localhost:8080)
- OpenVPN server: localhost:1194

### Keycloak Admin Console

To access the Keycloak Admin Console, navigate to [http://localhost:8080/](http://localhost:8080/).
You can log in using the following credentials:

- Username: `admin`
- Password: `insecure`

## Stopping the Demo

To stop the demo, press `Ctrl+C` in the terminal where the Docker Compose environment is running.
This will stop all the services and clean up the environment.

## Cleaning Up

If you want to remove all the services and clean up the environment, run the following command:

```bash
docker compose down -v
```
