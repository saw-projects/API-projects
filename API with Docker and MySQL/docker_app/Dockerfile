FROM python:3.12
WORKDIR /usr/src/app
COPY requirements.txt ./
RUN pip3 install -r requirements.txt
COPY . .
ENV INSTANCE_CONNECTION_NAME='hw3-baars:us-central1:businesses-instance'
ENV DB_NAME='lodgings-db'
ENV DB_USER='lodgings-user'
ENV DB_PASS='abcd'
ENV GOOGLE_APPLICATION_CREDENTIALS='./key.json'
ENV PORT=8000
EXPOSE ${PORT}
CMD [ "python", "main.py" ]
