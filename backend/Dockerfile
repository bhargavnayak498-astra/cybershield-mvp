version: '3.9'

services:
  mongodb:
    image: mongo:7
    container_name: cybershield-mongo
    restart: unless-stopped
    ports:
      - "27017:27017"
    environment:
      MONGO_INITDB_DATABASE: cybershield
    volumes:
      - mongo-data:/data/db
    healthcheck:
      test: ["CMD", "mongosh", "--quiet", "--eval", "db.runCommand({ ping: 1 }).ok"]
      interval: 10s
      timeout: 5s
      retries: 5

  backend:
    build:
      context: ./backend
    container_name: cybershield-backend
    depends_on:
      mongodb:
        condition: service_healthy
    ports:
      - "8000:8000"
    environment:
      MONGO_URI: mongodb://mongodb:27017
      MONGO_DB: cybershield
      APP_ENV: local
    command: uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

  frontend:
    build:
      context: ./frontend
    container_name: cybershield-frontend
    depends_on:
      - backend
    ports:
      - "5173:5173"
    environment:
      VITE_API_URL: http://localhost:8000
    command: npm run dev -- --host 0.0.0.0 --port 5173

volumes:
  mongo-data:
