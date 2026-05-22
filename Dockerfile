FROM python:3.10-slim

WORKDIR /code

# Dépendances système : build + WeasyPrint (GTK/Pango/Cairo)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libgobject-2.0-0 \
    libglib2.0-0 \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libpangocairo-1.0-0 \
    libffi-dev \
    libcairo2 \
    libgdk-pixbuf-2.0-0 \
    shared-mime-info \
    fonts-dejavu-core \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 7860

RUN chmod +x /code/entrypoint.sh
ENTRYPOINT ["/code/entrypoint.sh"]
