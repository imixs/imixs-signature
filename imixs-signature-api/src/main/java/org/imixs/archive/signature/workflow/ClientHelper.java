package org.imixs.archive.signature.workflow;

import java.util.Optional;
import java.util.logging.Logger;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.metrics.MetricRegistry;
import org.eclipse.microprofile.metrics.annotation.RegistryType;
import org.imixs.melman.BasicAuthenticator;
import org.imixs.melman.DocumentClient;

/**
 * Helper Class to return a rest api DocumentClient
 * 
 * 
 * @author rsoika
 * @version 1.0
 */
@ApplicationScoped
public class ClientHelper {

    public static final String SIGNATURE_SERVICE_ENDPOINT = "signature.service.endpoint";
    public static final String SIGNATURE_SERVICE_USER = "SIGNATURE_SERVICE_USER";
    public static final String SIGNATURE_SERVICE_PASSWORD = "SIGNATURE_SERVICE_PASSWORD";
    public static final String SIGNATURE_SERVICE_AUTHMETHOD = "SIGNATURE_SERVICE_AUTHMETHOD";
   
    @Inject
    @ConfigProperty(name = SIGNATURE_SERVICE_ENDPOINT)
    Optional<String> signatureAPIEndpoint;

    @Inject
    @ConfigProperty(name = SIGNATURE_SERVICE_USER)
    Optional<String> signatureServiceUser;

    @Inject
    @ConfigProperty(name = SIGNATURE_SERVICE_PASSWORD)
    Optional<String> signatureServicePassword;

    @Inject
    @ConfigProperty(name = SIGNATURE_SERVICE_AUTHMETHOD)
    Optional<String> signatureServiceAuthMethod;

    @Inject
    @RegistryType(type = MetricRegistry.Type.APPLICATION)
    MetricRegistry metricRegistry;

    boolean mpMetricNoSupport = false;
    private static Logger logger = Logger.getLogger(ClientHelper.class.getName());

    /**
     * Helper method to initalize a Melman Workflow Client based on the current
     * archive configuration.
     */
    public DocumentClient initDocumentClient() {

        logger.finest("...... SIGNATURE_SERVICE_ENDPOINT = " + signatureAPIEndpoint.get());

        DocumentClient documentClient = new DocumentClient(signatureAPIEndpoint.get());

        // We only support basic auth method here
        if ("Basic".equalsIgnoreCase(signatureServiceAuthMethod.get())) {
           
            // default basic authenticator
            BasicAuthenticator basicAuth = new BasicAuthenticator(signatureServiceUser.get(),
                    signatureServicePassword.get());
            // register the authenticator
            documentClient.registerClientRequestFilter(basicAuth);
        }
        return documentClient;
    }
}
