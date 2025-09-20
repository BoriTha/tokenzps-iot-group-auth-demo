FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Expose the port Flask will run on
EXPOSE 5000

CMD ["python", "fog_app.py"]
