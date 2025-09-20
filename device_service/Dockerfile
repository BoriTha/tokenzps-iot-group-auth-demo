FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Port for device's own Flask server (if leader needs to call it)
EXPOSE 5001
CMD ["python", "device_app.py"]
