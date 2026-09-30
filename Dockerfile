FROM node:18-slim

# index.js 运行时必需：openssl（生成自签 TLS 证书）、unzip（解压 Xray-core）
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssl unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev

COPY index.js ./

ENV PORT=3000
EXPOSE 3000

CMD ["node", "index.js"]
