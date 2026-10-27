# ============================================================================
#  Dockerfile  -  Servicio de cifrado
#  >>> VERSION INSEGURA (rama inseguro) <<<
#  Contiene malas practicas INTENCIONADAS que Trivy debe reportar.
# ============================================================================

# CORREGIDO [VULN-11] Imagen base "latest" (no reproducible) y pesada, con muchos
#   paquetes de sistema vulnerables. La solucion es una etiqueta fija y una
#   imagen slim (p.ej. node:20-slim).  CWE-1104 / mala practica de imagen.
#Mof Fanny FROM node:latest
FROM node:20-slim AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY *.js ./
FROM node:20-slim
WORKDIR /app
RUN useradd --system --no-create-home appuser
COPY --from=build /app /app
RUN chown -R appuser:appuser /app
USER appuser
EXPOSE 3000
CMD ["node","servidor.js"]
