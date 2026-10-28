# Stage 1: build the React app. Stage 2: serve the files with nginx.
FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
# These are baked into the JavaScript bundle (DEV ONLY, see .env.example).
ARG VITE_API_URL=http://localhost:8000
ARG VITE_ADMIN_KEY=
ENV VITE_API_URL=$VITE_API_URL VITE_ADMIN_KEY=$VITE_ADMIN_KEY
RUN npm run build

FROM nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
