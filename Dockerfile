FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --production
COPY . .
RUN mkdir -p logs
EXPOSE 3001
CMD ["node", "src/server.js"]
