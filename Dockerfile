#Base image with Python already installed
FROM python:3.12-slim

# Working directory inside the container
WORKDIR /app

# Copy requirements first so Docker can cache this layer
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# copy the rest of the project
COPY . .

# Port the API will listen on
EXPOSE 8000

# Command that starts the API
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]