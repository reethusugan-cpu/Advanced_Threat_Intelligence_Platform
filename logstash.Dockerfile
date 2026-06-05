FROM docker.elastic.co/logstash/logstash:8.12.0

# Switch to root temporarily to configure directory permissions
USER root

# Create the tracking directory expected by your Logstash config and grant ownership
RUN mkdir -p /opt/logstash-mongodb && chown -R logstash:root /opt/logstash-mongodb

# Switch back to the standard logstash user for security compliance
USER logstash

# Install the MongoDB input plugin
RUN logstash-plugin install logstash-input-mongodb
