#!/bin/bash

# Path to the flag file
FLAG_FILE="/app/flask_db_initialized.flag"

# Check if the flag file exists
if [ ! -f "$FLAG_FILE" ]; then
    # Run the flask db initialization commands
    flask db init
    flask db migrate -m "initial migration"
    flask db upgrade

    # Create the flag file to indicate completion
    touch "$FLAG_FILE"
fi

# Start Flask
flask run --host 0.0.0.0 --port 5000
