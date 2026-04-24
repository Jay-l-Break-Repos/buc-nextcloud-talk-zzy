FROM node:20-slim

WORKDIR /app

COPY repo/package.json repo/package-lock.json ./

RUN npm install --legacy-peer-deps

COPY repo/ .

EXPOSE 9090

CMD ["node", "app.js"]
