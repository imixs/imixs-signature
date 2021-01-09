FROM jboss/wildfly:20.0.1.Final

LABEL description="Imixs-Signature-Service"
LABEL maintainer="ralph.soika@imixs.com"

# Deploy artefact
ADD ./target/imixs-signature-service.war /opt/jboss/wildfly/standalone/deployments/

# Run with management interface
CMD ["/opt/jboss/wildfly/bin/standalone.sh", "-b", "0.0.0.0", "-bmanagement", "0.0.0.0"]   