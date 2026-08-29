# RepoHunter needs a git binary and a writable temp directory, so it runs as a
# container rather than on a Lambda-style serverless runtime.
FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

FROM node:22-alpine AS build
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM node:22-alpine AS runtime
WORKDIR /app
# The one dependency that is not on npm.
RUN apk add --no-cache git
ENV NODE_ENV=production
COPY --from=deps /app/node_modules ./node_modules
COPY --from=build /app/.next ./.next
COPY package.json next.config.ts ./
EXPOSE 3000
CMD ["npx", "next", "start"]
