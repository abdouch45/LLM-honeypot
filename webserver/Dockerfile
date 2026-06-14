FROM node:20-alpine

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install --production

COPY . ./

ENV PORT=8081
ENV LOG_FILE_PATH=logs/logs.json

EXPOSE 8081

CMD ["node", "app.js"]
