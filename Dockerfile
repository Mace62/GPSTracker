FROM python:3.6.8
WORKDIR /app
COPY ./requirements.txt /app
RUN pip install --upgrade pip
RUN pip install -r requirements.txt
COPY . .
EXPOSE 5000
ENV FLASK_APP=app.py
RUN echo "stripe_api_key=${STRAPI_SECRET}" > /app/secret.py

# Copy the startup script
COPY start.sh /app/start.sh
# Make the startup script executable
RUN chmod +x /app/start.sh

CMD ["/app/start.sh"]
