FROM node:21-alpine3.18

COPY package.json ./package.json
RUN npm install

COPY server.js /usr/src/app/server.js

EXPOSE 3000

CMD ["node", "/usr/src/app/server.js"]
