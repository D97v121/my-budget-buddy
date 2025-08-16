FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Copy project files
COPY . .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose port 8000
EXPOSE 8000

# Run the app with Gunicorn
CMD ["gunicorn", "wsgi:app", "-w", "3", "-b", "0.0.0.0:8080", "--timeout", "120""]

