# Advanced Threat Intelligence Platform
Week 1: Infrastructure and Schema Setup
1. Project Overview

Project Name: Artificial Threat Intelligence Platform (ATIP)

Objective: A containerized solution to fetch, store, and visualize cyber threat indicators using Python and MongoDB.

2. Prerequisites

OS: Kali Linux (Recommended)

Tools: Docker, Docker-Compose, Python 3.10+, MongoDB, Git, GitHub

IDE: Antigravity or VS Code

3. Local Setup Instructions
This prevents "it works on my machine" syndrome.

3.1 Clone the Repository:
bash
git clone <your-repo-link>

3.2 Infrastructure Setup:
Navigate to the project folder and run:
bash
docker-compose up -d

3.3 Python Environment:
bash
python3 -m venv threat-intel-venv
source threat-intel-venv/bin/activate
pip install -r requirements.txt

3.4 Install Python Libraries:
bash
pip install requests pymongo python-dotenv pandas

3.5 Database Access:
View the database at http://localhost:8081

Username: admin
Password: password123

3.6 MongoDB & Docker Management
Our platform uses Docker to ensure the database environment is identical for every team member. Use these commands to manage your local instance.

1. Starting the Environment
To start the database and the Web UI in the background, run:

Bash
docker-compose up -d
Wait about 10 seconds for the containers to fully initialize before running your Python scripts.

2. Checking Status
To verify that the containers are running and see which ports they are using:

Bash
docker ps
You should see atip-mongodb on port 27017 and atip-mongo-gui on port 8081.

3. Viewing Live Logs
If your Python script is failing to connect, check the database logs to see if it’s receiving the request:

Bash
# View all logs
docker-compose logs -f

# View only the database logs
docker logs -f atip-mongodb
4. Stopping and Cleaning Up
When you are finished working for the day:

Bash
# Stops and removes the containers (keeps your data safe in the volume)
docker-compose down
5. The "Full Reset" (Use with Caution)
If your database becomes corrupted or you want to start with a totally fresh slate (deleting all stored threat data):

Bash
# This stops containers and deletes the stored data volumes
docker-compose down -v

3.7 Database Connection Details
For your Python scripts to communicate with the database, use the following configuration (standardize this in your .env files):

Host: localhost (if running script on Kali) or atip-mongodb (if running script inside Docker)

Port: 27017
Username: admin
Password: password123

Auth Source: admin

Connection String Example:
mongodb://admin:password123@localhost:27017/atip?authSource=admin

3.8 Manual Container Execution
If you prefer to run the database manually without using docker-compose, use the following command. This is useful for quick testing:

Bash
docker run -d \
  --name atip-mongodb \
  -p 27017:27017 \
  -v mongo-data:/data/db \
  -e MONGO_INITDB_ROOT_USERNAME=admin \
  -e MONGO_INITDB_ROOT_PASSWORD=password123 \
  mongo:4.4

Breakdown of the flags for the team:

-d: Runs the container in "Detached" mode (background).

--name: Assigns a specific name to the container so we can find it easily.

-p 27017:27017: Maps the container's port to your Kali machine's port.

-v: Creates a persistent volume so your data isn't lost when the container stops.

-e: Sets the Environment variables for the login credentials.

🛑 Useful "Kill" Commands
Sometimes a container gets stuck or you want to wipe it quickly. Include these in the Troubleshooting section:

Stop the database:
docker stop atip-mongodb

Remove the container:
docker rm atip-mongodb

Remove the volume (Wipe all data):
docker volume rm mongo-data

4. Coding Standards (The "Team Contract")
To keep the code clean as all four members start pushing their changes, establish these rules now:

Naming Conventions: Use snake_case for functions and variables (e.g., fetch_threat_data). Use PascalCase for classes.

Virtual Environments: Never push a venv folder to GitHub. Always update requirements.txt if you install a new library (pip freeze > requirements.txt).

Documentation: Every new function must include a Docstring explaining what it does.

Environment Variables: Sensitive data (like API keys for threat feeds) must stay in a .env file and never be hardcoded in main.py.

No Hardcoding: Never place API keys or passwords directly in the scripts. Use a .env file and the python-dotenv library.

5. Git Workflow
Branches: Never work directly on the main branch. Create a feature branch: git checkout -b feature/your-feature-name.

Commits: Write descriptive commit messages (e.g., "Fix: updated MongoDB connection logic").

No VENV: Never commit your venv/ folder. Ensure it is listed in your .gitignore.

6. Directory Structure
Explains what each folder does so they don't put files in the wrong place.

/database: Contains MongoDB configuration and init scripts.

/feeds: Python scripts for individual threat intelligence sources.

/utils: Helper functions (logging, data cleaning).

docker-compose.yml: Orchestration for the DB and UI.

7. Troubleshooting
If you encounter issues during setup, check these common solutions before reaching out to the Team Lead.

7.1 Docker Port Conflicts
Issue: Error message stating Bind for 0.0.0.0:27017 failed: port is already allocated or Container name is already in use.
Solution: This usually happens if a previous instance didn't shut down correctly. Run:

Bash
# Force remove the conflicting containers
docker rm -f atip-mongodb atip-mongo-gui

# Restart the infrastructure
docker-compose up -d

7.2 Database Connection Refused
Issue: main.py fails to connect to MongoDB.
Solution: 
1. Check if the database is actually running with docker ps.
2. Ensure your connection string in the code matches the service name in docker-compose.yml.

# Advanced Threat Intelligence & Automated Incident Response Platform

An asynchronous, containerized DevSecOps platform designed to ingest multi-structured Indicators of Compromise (IoCs) from open-source threat intelligence feeds, synchronize metadata across distributed datastores, and execute automated kernel-level perimeter isolation and incident response mitigation.

## Documentation
- 📄 [Architecture Document](docs/ATIP_Architecture_Document.md)


---

