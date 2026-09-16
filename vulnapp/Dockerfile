# heimdall-vulnapp: deliberately vulnerable target. Do not deploy anywhere public.
FROM python:3.12-slim

WORKDIR /app
RUN pip install --no-cache-dir \
    "fastapi>=0.110" "uvicorn>=0.29" "jinja2>=3.1" "httpx>=0.27" "PyJWT>=2.8"

COPY . /app/vulnapp/

ENV HOST=0.0.0.0 PORT=8000
EXPOSE 8000
CMD ["python", "-m", "vulnapp"]
