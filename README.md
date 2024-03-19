[![Build, Push, and Run Docker Images](https://github.com/uol-feps-soc-comp2913-2324s2-classroom/team-project-team-8/actions/workflows/main.yml/badge.svg)](https://github.com/uol-feps-soc-comp2913-2324s2-classroom/team-project-team-8/actions/workflows/main.yml)

# How to run: GPS Tracker Docker Container

This repository has a Docker container for the GPS Tracker application. Below are the instructions to pull the container, set it up, and run it on your system.

## Prerequisites

Before proceeding, ensure you have Docker installed on your system. If you don't have Docker installed, you can download it from [Docker's official website](https://www.docker.com/get-started).

## Pulling the Docker Container

To pull the `gpstracker` Docker container, open your terminal and run the following command:

```bash
docker pull rigbytrash/gpstracker
```
This command will pull the latest version of the gpstracker container from Docker Hub.

## Running the Container
After pulling the container, you can run it using the following command:

```bash
docker run -p 5000:5000 rigbytrash/gpstracker
```
This command will start the GPS Tracker application and bind it to port 5000 of your host machine. This means you can access the application by navigating to http://localhost:5000 in your web browser.

You may also want to give the container a name from the get-go, via:

```bash
docker run --name thecontainername -p 5000:5000 rigbytrash/gpstracker
```

## Stopping the Container
To stop the running container, you can press CTRL+C in the terminal where it's running. Alternatively, you can stop the container from another terminal window using the following command:

```bash
docker stop [CONTAINER_ID]
```
Replace `[CONTAINER_ID]` with the actual ID of your running container. You can find the container ID by running docker ps. You may also use the name of the container.

# How to run: Locally

## Prerequisites
### Set up a virtual environment (ensure you are using python version 3.6.8)

To create a virtual environment named flask, use the following command at the terminal:

```bash
python3 -m venv flask
```
To run the venv, type:

```bash
source flask/bin/activate
```

## Cloning the repository
Open your terminal and run the following command to clone the repository:
```bash
git clone https://github.com/uol-feps-soc-comp2913-2324s2-classroom/team-project-team-8.git
```

## Installing requirements
Once the virtual environment is created, and the repo is cloned, install the required modules using the following command:

```bash
pip install -r requirements.txt
```

## Initialise the database
Type the following commands in succession:
```bash
flask db init
flask db migrate
flask db upgrade
```

## Start the application
You can now start the application (and kill it at any time by pressing CTRL+C):
```bash
flask run
```
