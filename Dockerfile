FROM node:24-alpine AS dashboard-build
WORKDIR /workspace
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY app ./app
COPY build ./build
COPY public ./public
COPY worker ./worker
COPY .openai ./.openai
COPY next.config.ts postcss.config.mjs tsconfig.json vite.config.ts next-env.d.ts ./
RUN npm run build

FROM node:24-alpine AS dashboard-runtime
WORKDIR /workspace
ENV NODE_ENV=production
COPY --from=dashboard-build /workspace ./
EXPOSE 3000
CMD ["npm", "run", "start", "--", "--host", "0.0.0.0"]

FROM python:3.11-slim AS api-runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt pyproject.toml ./
RUN pip install --no-cache-dir -r requirements.txt
COPY policypilot ./policypilot
COPY policies ./policies
COPY fixtures ./fixtures
COPY scripts ./scripts
RUN mkdir -p /app/data
EXPOSE 8000
CMD ["uvicorn", "policypilot.api:app", "--host", "0.0.0.0", "--port", "8000"]
