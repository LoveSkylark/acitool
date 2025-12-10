FROM python:3.12-slim

# Build arguments
ARG VERIFY_SSL=false
ARG APIC_URL

# Environment variables
ENV VERIFY_SSL=${VERIFY_SSL} \
    APIC_URL=${APIC_URL} \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Set working directory
WORKDIR /app

# Copy requirements first for layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application scripts
COPY scripts/ /app/

# Create non-root user for security
RUN useradd -m -u 1000 -s /bin/bash aciuser && \
    chown -R aciuser:aciuser /app

# Create directory for token storage
RUN mkdir -p /home/aciuser/.aci && \
    chown -R aciuser:aciuser /home/aciuser/.aci

# Switch to non-root user
USER aciuser

# Set the entrypoint
ENTRYPOINT ["python3", "/app/acitool.py"]

# Default command (show help)
CMD ["--help"]
