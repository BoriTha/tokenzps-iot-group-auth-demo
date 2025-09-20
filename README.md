Secure IoT Group Authentication in a Fog Computing Environment

This project simulates a secure fog computing environment for Internet of Things (IoT) devices. It demonstrates a multi-phase cryptographic protocol for device registration, leader-based group authentication, and secure data transmission. The entire system is containerized using Docker and Docker Compose and includes an interactive admin shell for managing the simulation.

System Architecture

The simulation consists of three main components that interact within a Docker network. A central Fog Node acts as a trusted authority, managing device identity and orchestrating the security protocol. One IoT device is designated as the leader to coordinate authentication flows, while others act as base members. An administrative CLI provides a control plane to manage the entire simulation.

graph TD
    subgraph "Your Local Machine"
        User(fa:fa-user You) -- Interacts with --> Admin[Admin Shell]
    end

    subgraph "Docker Environment (iot_net)"
        Fog(fa:fa-server Fog Node)
        D1(fa:fa-microchip Device 1 - Leader)
        D2(fa:fa-microchip Device 2 - Base)
        DN(fa:fa-microchip ...More Devices)

        Admin -- Manages / Triggers --> Fog
        Admin -- Manages / Triggers --> D1
        Admin -- Manages / Triggers --> D2
        Admin -- Manages / Triggers --> DN
    end

    D1 <-->|Phases 1-6| Fog
    D2 <-->|Phases 1, 6| Fog
    DN <-->|Phases 1, 6| Fog

    D1 -- Coordinates Auth (Phases 3, 5) --> D2
    D1 -- Coordinates Auth (Phases 3, 5) --> DN

Features

- Containerized Services: The entire environment is defined in docker-compose.yml for easy, one-command deployment.

- Dynamic Device Management: Add, remove, and list devices in real-time using the admin shell without restarting the system.

- Advanced Security Protocol: Implements a multi-phase protocol for robust security:
	- Phase 1: PUF-based device registration and group polynomial setup.

	- Phase 2: Leader authentication using a Schnorr Zero-Knowledge Proof (ZKP).

	- Phase 3: Secure delegation of group token shares via a secret sharing scheme.

	- Phase 4: Collective group authentication by reconstructing a secret polynomial.

	- Phase 5: Dynamic session token generation and secure distribution.

	- Phase 6: Authenticated data transmission using the ChaCha20-Poly1305 AEAD cipher.


- Interactive Admin CLI: A powerful, command-driven tool to manage the simulation, inspect state, and trigger protocol flows.

The Security Protocol Flow


The core of this project is the multi-phase security protocol designed to establish trust and enable secure communication.


1. Phase 1: Registration & Group Polynomial Setup


	- Each device registers with the Fog using a simulated Physically Unclonable Function (PUF) to generate a unique coordinate (x, y).

	- The Fog selects a subset of registered devices and uses their coordinates to construct a group polynomial P(x) using Lagrange interpolation. The group's master secret is defined as S = P(0).


2. Phase 2: Leader Authentication (ZKP)


	- The leader device proves its identity to the Fog by providing a Schnorr non-interactive zero-knowledge proof of its private elliptic curve key.

	- Upon success, the Fog establishes a secure session with the leader by sending it an RSA-encrypted symmetric key.


3. Phase 3: Group Share Delegation


	- The leader requests the Fog to create and delegate shares of the group secret S. The Fog uses a secret sharing scheme to generate these shares and sends them to the leader for secure distribution to group members.


4. Phase 4: Group Authentication


	- The leader orchestrates a group-wide authentication by collecting signed coordinates from all members.

	- The Fog verifies the signatures and uses the collected points to reconstruct the secret S. A successful reconstruction verifies the group's integrity and establishes an authenticated session.


5. Phase 5: Session Token Generation


	- With an authenticated session active, the leader requests a new token polynomial for data transmission.

	- The Fog generates a new secret and polynomial, creating unique token points for each legitimate device. These points are encrypted with the session key and sent to the leader for distribution.


6. Phase 6: Authenticated Data Transmission


	- Each device uses its unique token point (x_i, y_i) to derive a 256-bit symmetric key.

	- This key is used with the ChaCha20-Poly1305 cipher to encrypt and send data to the Fog, which verifies and decrypts it.

    Getting Started

Prerequisites

- Docker

- Docker Compose (Included with Docker Desktop)

- Python 3.8+ (for running the admin shell)

Installation & Launch

1. Clone the repository:
    git clone https://github.com/your-username/your-repo-name.git
    cd your-repo-name   

2. Build and start the services:
    docker-compose up --build -d

This command builds the Docker images for the fog and device services and starts them in detached mode. The initial orchestration flow (Phases 1-6) will run automatically.

Usage

Once the services are running, manage and interact with the simulation using the Admin Shell.

1. Launch the shell:
    python3 admin_shell.py

You will be greeted with the fog-admin> prompt. Type help for a full list of commands.

2. Key Commands:

- status: Get a comprehensive JSON dump of the Fog Node's current state, including devices, polynomial details, and active session info.

- list: Display a simple list of all devices and their registration status.

- add_device: Dynamically starts a new device container.

- add_many <count>: A helper to quickly spin up and register multiple new devices.

- remove_device <device_id>: Stops and removes a device, revokes its token, and deletes its registration data from the Fog.

- resync: Triggers a full re-authentication flow (Phases 1-5), useful after adding or removing devices.

- cleanup: Removes all dynamically added ("admin-created") devices and cleans up stale entries in the Fog's registry.

- exit or quit: Exit the admin shell.

Configuration

You can customize the initial state of the simulation by modifying the environment variables within the docker-compose.yml file.

- fog_service:
	- NUM_DEVICES: The initial number of devices the fog expects.

	- THRESHOLD_T: The minimum number of devices required to reconstruct the group secret.

	- DELEGATION_THRESHOLD_T_PRIME: The threshold for the secondary secret sharing scheme.

	- WIPE_STORAGE_ON_START: Set to true to clear all persistent fog data on startup.

- device_...:
	- DEVICE_ROLE: Can be leader or base. There must be exactly one leader.

	- WIPE_DEVICE_STORAGE_ON_START: Set to true to clear the device's local state on startup.

Project Structure

.
├── admin_shell.py            # The interactive admin CLI tool
├── common_utils.py           # Shared cryptographic functions and helpers
├── docker-compose.yml        # Defines the services, networks, and volumes
├── fog_service/
│   ├── fog_app.py            # The main Flask application for the Fog Node
│   ├── Dockerfile
│   └── requirements.txt
├── device_service/
│   ├── device_app.py         # The main Flask application for the IoT Device
│   ├── Dockerfile
│   ├── requirements.txt
│   └── unencrypted_recorder.py # Helper for logging data for audit
└── README.md                 # This file

License

This project is licensed under the MIT License. See the LICENSE file for details.