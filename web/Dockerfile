FROM node:20-alpine

WORKDIR /app

# Install node dependencies
COPY package.json ./
# Use npm install instead of npm ci because package-lock.json may be absent in the build context
RUN npm install --production --legacy-peer-deps --no-audit --no-fund

# Copy project files
COPY . /app

# Ensure output & stats dirs exist
RUN mkdir -p /www /data/stats || true
RUN cp -r /app/static /www || true

ENV PORT=8000

EXPOSE 8000

CMD ["npm","start"]