FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 MPLBACKEND=Agg
WORKDIR /app

COPY requirements.txt requirements-dashboard.txt ./
ARG WITH_DASHBOARD=1
RUN pip install -r requirements.txt && if [ "$WITH_DASHBOARD" = "1" ]; then pip install -r requirements-dashboard.txt; fi

COPY . .
# Train the small classifier from the committed dataset at build time (offline, ~seconds).
RUN python -m classifier.train

EXPOSE 8080 8081 8501
CMD ["uvicorn", "tripwire.server:app", "--host", "0.0.0.0", "--port", "8080"]
