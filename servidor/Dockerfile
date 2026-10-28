# ---------- Etapa 1: construccion ----------
FROM node:24-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY *.js ./

# ---------- Etapa 2: imagen final ----------
FROM node:24-alpine
WORKDIR /app
COPY --from=build --chown=node:node /app /app
# En ejecucion solo hace falta node: se quitan npm, yarn y corepack
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
           /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack \
           /opt/yarn-* /usr/local/bin/yarn /usr/local/bin/yarnpkg
USER node
EXPOSE 3000
CMD ["node", "servidor.js"]