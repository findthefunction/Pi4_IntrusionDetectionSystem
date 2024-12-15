# Use an official Python runtime as a parent image
FROM python:3.12-slim

# Set environment variables
# Prevent Python from writing .pyc files
ENV PYTHONDONTWRITEBYTECODE=1 
# Ensure stdout and stderr are not buffered
ENV PYTHONUNBUFFERED=1         

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Install pipenv
RUN pip install --upgrade pip
RUN pip install pipenv

# Set work directory
WORKDIR /app

# Copy Pipfile and Pipfile.lock
COPY Pipfile Pipfile.lock /app/

# Install Python dependencies
RUN pipenv install --deploy --ignore-pipfile

# Copy the rest of the application code
COPY . /app/

# Expose any necessary ports (if you plan to add a dashboard later)
# EXPOSE 8000

# Define the default command to run the IDS
CMD ["pipenv", "run", "python", "main.py"]
