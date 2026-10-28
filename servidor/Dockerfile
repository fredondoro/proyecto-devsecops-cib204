# ============================================================================
#  Dockerfile  -  Servicio de cifrado
# ============================================================================

# Etapa 1: Construcción (compilaciones y preparación de dependencias)
FROM node:20-slim AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY *.js ./

# Etapa 2: Imagen final (Alpine para 0 vulnerabilidades de SO en Trivy)
FROM node:20-alpine
WORKDIR /app

# Parchear paquetes nativos de Alpine a la versión más reciente
RUN apk update && apk upgrade --no-cache

# Crear el usuario no root equivalente para Alpine
RUN addgroup -S appuser && adduser -S appuser -G appuser

# Copiar el código desde la etapa de compilación
COPY --from=build /app /app
RUN chown -R appuser:appuser /app
USER appuser

EXPOSE 3000
CMD ["node", "servidor.js"]