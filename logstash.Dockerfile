FROM docker.elastic.co/logstash/logstash:8.12.0

# Install the MongoDB input plugin
RUN logstash-plugin install logstash-input-mongodb
