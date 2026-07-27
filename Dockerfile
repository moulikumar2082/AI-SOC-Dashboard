FROM python:3.12-slim

WORKDIR /app

# Install system dependencies for ReportLab and C extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libfreetype6-dev \
    liblcms2-dev \
    libopenjp2-7-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create required directories
RUN mkdir -p uploads reports certs

EXPOSE 5000

ENV PORT=5000
ENV USE_HTTPS=false

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "run:app"]
