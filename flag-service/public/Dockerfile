
FROM python:3.12-slim

WORKDIR /app
RUN pip install Flask PyCryptodome gunicorn
COPY . .

CMD ["gunicorn", "-b", "0.0.0.0:8000", "app:app"]
