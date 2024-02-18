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

1. Open a terminal.
2. Navigate to the directory where the `docker-compose.yaml` file is located.
3. Run the following command to start the Docker Compose environment:

   ```bash
   docker-compose up
   ```
   This command will start all the necessary services. It may take a few minutes for all services to start and initialize.

4. After all services have started, a client configuration for OpenVPN will be created in the `config/client/` directory.
   This configuration can be imported into any OpenVPN client.
   Viscosity may not work here, because the client block local network access.
5. Import the client configuration into your OpenVPN client.
6. Connect to the OpenVPN server using the demo user credentials (username: `demo`, password: `demo123`).

After connecting, you should be able to see the `openvpn-auth-oauth2` application in action.

Please note that this is a demo setup and is not suitable for production use.
