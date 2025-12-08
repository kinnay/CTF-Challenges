
FROM python:3.12-slim

WORKDIR /app
RUN pip install Flask PyCryptodome PyJWT cryptography gunicorn
COPY . .

EXPOSE 8000

CMD ["gunicorn", "-b", "0.0.0.0:8000", "app:app"]
