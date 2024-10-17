# Use a lightweight Python image
FROM python:3.9-slim

# Set the working directory
WORKDIR /app

# Copy the application code
COPY alice.py .
COPY bob.py .

# By default, run nothing; use docker exec to run individual scripts
CMD ["tail", "-f", "/dev/null"]
