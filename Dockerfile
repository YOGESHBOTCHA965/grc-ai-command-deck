FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# reportlab may need basic font and rendering libs on slim images.
RUN apt-get update \
    ; apt-get install -y --no-install-recommends \
      build-essential \
      libfreetype6 \
      libjpeg62-turbo \
      libpng16-16 \
      fonts-dejavu-core \
    ; rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY . .

RUN mkdir -p data outputs data/cache && chmod -R 777 data outputs

EXPOSE 7860

CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PORT:-7860}"]
