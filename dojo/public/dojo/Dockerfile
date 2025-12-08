
FROM node:22-slim

WORKDIR /app
RUN npm install ejs express jsonwebtoken jwk-to-pem memory-cache
COPY . .

EXPOSE 3000

CMD ["node", "index.js"]
