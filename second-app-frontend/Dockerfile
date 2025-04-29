# Build aşaması
FROM node:18-alpine AS build

WORKDIR /app

# Bağımlılıkları kopyala ve yükle
COPY package.json package-lock.json ./
RUN npm ci

# Kaynak kodları kopyala ve build et
COPY . .
RUN npm run build

# Çalışma zamanı aşaması
FROM nginx:1.23-alpine

# Nginx konfigürasyonu
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Build çıktısını Nginx'in servis edeceği dizine kopyala
COPY --from=build /app/build /usr/share/nginx/html

# 80 portunu aç
EXPOSE 80

# Nginx başlat
CMD ["nginx", "-g", "daemon off;"]