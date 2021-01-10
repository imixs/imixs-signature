package org.imixs.signature.api;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Optional;
import java.util.logging.Logger;

import javax.inject.Inject;
import javax.inject.Named;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.bouncycastle.operator.OperatorCreationException;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.imixs.signature.ca.CAService;
import org.imixs.signature.pdf.SigningService;
import org.imixs.workflow.ItemCollection;
import org.imixs.workflow.xml.XMLDataCollectionAdapter;
import org.imixs.workflow.xml.XMLDocument;
import org.imixs.workflow.xml.XMLDocumentAdapter;

/**
 *  The X509CertificateAdapter generate a new certificate based on the x509
 * attributes stored in the current document
 * 
 * @author rsoika
 *
 */ 
@Named
@Path("certificate")
@Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
public class X509CertificateResource {
    public static final String PDF_REGEX = "^.+\\.([pP][dD][fF])$";

    @Inject 
    @ConfigProperty(name = SigningService.ENV_SIGNATURE_ROOTCERT_ALIAS)
    Optional<String> rootCertAlias;

    @Inject
    @ConfigProperty(name = SigningService.ENV_SIGNATURE_ROOTCERT_PASSWORD)
    Optional<String> rootCertPassword;

    @Inject
    SigningService signatureService;

    @Inject
    CAService caService;

  
 
    private static Logger logger = Logger.getLogger(X509CertificateResource.class.getName());

    /**
     * POST Request with a ItemCollection containing a PDF fileData.
     * <p>
     * A valid xml document structure is expected with the following items:
     * 
     * $fileData - containing the pdf file to sign
     * 
     * autocreate,rootsignature
     * 
     * :
     * 
     * 
     * </p>
     * The method returns a XMLDocument with the signed document
     * 
     * 
     * @param requestXML - workitem data
     * @return - XMLDocument with option list
     */
    @POST
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public Response signPDF(XMLDocument xmlDocument) {
        ItemCollection document = XMLDocumentAdapter.putDocument(xmlDocument);
        String certAlias = document.getItemValueString("txtname");
        logger.finest(".......adding new certificate for userid '" + certAlias + "'");

            try {
                caService.createCertificate(certAlias, document);
            } catch (UnrecoverableKeyException | InvalidKeyException | KeyStoreException | NoSuchAlgorithmException
                    | NoSuchProviderException | OperatorCreationException | CertificateException | SignatureException
                    | IOException e) {
                logger.warning("Failed to query documents: " + e.getMessage());
                e.printStackTrace();
            }
      
        logger.info("**************** FINISHED ***********************");
        // log the stats XMLDocument object....
        ItemCollection stats = new ItemCollection();

        logger.info("**************** FINISHED ***********************");

        // return response
        return Response.ok(XMLDataCollectionAdapter.getDataCollection(stats), MediaType.APPLICATION_XML).build();
    }

}