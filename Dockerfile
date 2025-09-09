FROM python:3.10-slim

# Install system dependencies needed for nmap and subfinder
RUN apt-get update && apt-get install -y nmap wget unzip

# Download and install Subfinder
RUN wget https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip && \
    unzip subfinder_2.6.6_linux_amd64.zip && \
    mv subfinder /usr/local/bin/ && \
    rm subfinder_2.6.6_linux_amd64.zip

# Set working directory
WORKDIR /app

# Copy requirements first to leverage Docker cache
COPY requirements.txt requirements.txt

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Expose port
EXPOSE 5000

# Run the application with Gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
