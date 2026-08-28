# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Install system security tools (Removed enum4linux/nikto to fix exit code 100)
RUN apt-get update && apt-get install -y \
    nmap \
    whois \
    dnsutils \
    iproute2 \
    procps \
    openssl \
    smbclient \
    && rm -rf /var/lib/apt/lists/*

# Copy the requirements file into the container
COPY requirements.txt .

# Install Python packages
RUN pip install --no-cache-dir -r requirements.txt

# Copy the current directory contents into the container
COPY . .

# Expose port 5000 for Flask
EXPOSE 5000

# Command to run the application
CMD ["python", "app.py"]