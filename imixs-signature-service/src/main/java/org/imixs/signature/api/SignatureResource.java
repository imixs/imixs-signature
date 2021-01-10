package org.imixs.signature.api;

import java.awt.geom.Rectangle2D;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Optional;
import java.util.logging.Logger;
import java.util.regex.Pattern;

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
import org.imixs.signature.pdf.cert.CertificateVerificationException;
import org.imixs.signature.pdf.cert.SigningException;
import org.imixs.workflow.FileData;
import org.imixs.workflow.ItemCollection;
import org.imixs.workflow.WorkflowKernel;
import org.imixs.workflow.exceptions.ProcessingErrorException;
import org.imixs.workflow.xml.XMLDataCollectionAdapter;
import org.imixs.workflow.xml.XMLDocument;
import org.imixs.workflow.xml.XMLDocumentAdapter;

/**
 * The Signature Resoucre is the Rest Service API Endpoint for signing a
 * document attached to a Imixs ItemCollection
 * 
 * @author rsoika
 *
 */
@Named
@Path("sign")
@Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
public class SignatureResource {
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

    private static Logger logger = Logger.getLogger(SignatureResource.class.getName());

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

        boolean autocreate = true;
        boolean rootsignature = false;
        String file_pattern = PDF_REGEX;
        float positionx = 30;
        float positiony = 700;
        float dimensionw = 170;
        float dimensionh = 100;

        ItemCollection document = XMLDocumentAdapter.putDocument(xmlDocument);
        ItemCollection signedDocument=new ItemCollection();
        try {
            // do we have file attachments?
            List<String> fileNames = document.getFileNames();
            if (fileNames.size() > 0) {

                // read signature options

                if (document.hasItem("autocreate")) {
                    autocreate = document.getItemValueBoolean("autocreate");
                }
                if (document.hasItem("rootsignature")) {
                    rootsignature = document.getItemValueBoolean("rootsignature");
                }
                if (document.hasItem("position-x")) {
                    positionx = document.getItemValueFloat("position-x");
                }
                if (document.hasItem("position-y")) {
                    positiony = document.getItemValueFloat("position-y");
                }
                if (document.hasItem("dimension-w")) {
                    dimensionw = document.getItemValueFloat("dimension-w");
                }
                if (document.hasItem("dimension-h")) {
                    dimensionh = document.getItemValueFloat("dimension-h");
                }
                if (document.hasItem("filepattern")) {
                    // the file pattern is optional
                    file_pattern = document.getItemValueString("filepattern");
                }

                // do we have files matching the file pattern?
                Pattern filePatternMatcher = Pattern.compile(file_pattern);
                for (String fileName : fileNames) {
                    // did the file math our file pattern? We expect only pdf files!
                    if (filePatternMatcher.matcher(fileName).find()) {
                        // yes! start signing....
                        // we assume an empty password for certificate
                        String certPassword = "";
                        String certAlias = null;

                        // Test if the a signature with the root certificate is requested
                        if (rootsignature && rootCertAlias.isPresent()) {
                            certAlias = rootCertAlias.get();
                            // set SIGNATURE_ROOTCERT_PASSWORD
                            if (rootCertPassword.isPresent()) {
                                certPassword = rootCertPassword.get();
                            }

                            // test existence of default certificate
                            if (!caService.existsCertificate(certAlias)) {
                                throw new ProcessingErrorException(this.getClass().getSimpleName(), "SIGNING_ERROR",
                                        "Root certificate '" + certAlias + "' does not exist!");
                            }
                            logger.info("......signing " + fileName + " with root certificate '" + certAlias + "'...");
                        } else {
                            // signature with user certificate....
                            // compute alias validate existence of certificate
                            certAlias = document.getItemValueString("certAlias");
                            logger.info("......signing " + fileName + " by '" + certAlias + "'...");

                            // test if a certificate exits....
                            if (!caService.existsCertificate(certAlias)) {
                                if (autocreate) {
                                    // create new certificate....
                                    // we expect that the document provides the correspondign x509 items
                                    // (o,ou,city,state,country)
                                    caService.createCertificate(certAlias, document);
                                } else {
                                    throw new CertificateVerificationException(
                                            "certificate for alias '" + certAlias + "' not found.");
                                }
                                // test existence of default certificate
                                if (!caService.existsCertificate(certAlias)) {
                                    throw new ProcessingErrorException(this.getClass().getSimpleName(), "SIGNING_ERROR",
                                            "No certificate exists for user '" + certAlias + "'");
                                }
                            }
                        }

                        // read the file data...
                        FileData fileData = document.getFileData(fileName);
                        byte[] sourceContent = fileData.getContent();

                        byte[] signedContent = null;
                        // in case of a rootsignature we do not generate a signature visual!
                        if (rootsignature) {
                            signedContent = signatureService.signPDF(sourceContent, certAlias, certPassword, false);
                        } else {
                            byte[] signatureImage = null;
                            // we reisize the signature image to a maximum height of the half of the
                            // signature rect

                            FileData fileDataSignature = getSignatureImage(document);
                            if (fileDataSignature != null) {
                                // resize the signature image to the half of the signature rect

                                // fileDataSignature=resizeSignature(fileDataSignature,(int) (dimensionh/2));
                                signatureImage = fileDataSignature.getContent();
                            }

                            // if we have already a signature we move the x position....
                            int signatureCount = document.getItemValueInteger("signature.count");
                            if (signatureCount > 0) {
                                positionx = positionx + (signatureCount * dimensionw + 10);
                            }
                            Rectangle2D humanRect = new Rectangle2D.Float(positionx, positiony, dimensionw, dimensionh);
                            // create signature withvisual
                            signedContent = signatureService.signPDF(sourceContent, certAlias, certPassword, false,
                                    humanRect, "Signature" + signatureCount, signatureImage,
                                    document.getItemValueString(WorkflowKernel.WORKFLOWSTATUS));

                            document.setItemValue("signature.count", signatureCount + 1);
                        }

                        // ad the signed pdf file to the signed workitem
                        FileData signedFileData = new FileData(fileName, signedContent, "application/pdf", null);
                        signedDocument.addFileData(signedFileData);
                        logger.info("......" + fileName + " signed");
                    }
                   
                }

            }
        } catch (CertificateVerificationException | UnrecoverableKeyException | InvalidKeyException | KeyStoreException
                | NoSuchAlgorithmException | NoSuchProviderException | OperatorCreationException | CertificateException
                | SignatureException | IOException | SigningException e) {
            logger.warning("Failed to query documents: " + e.getMessage());
            e.printStackTrace();
        }

        
        // return response signedDocument
        return Response.ok(XMLDataCollectionAdapter.getDataCollection(signedDocument), MediaType.APPLICATION_XML).build();
    }

    /**
     * This helper method test if the current document holds a signature image. The
     * expected file name is 'signature.jpg'
     * 
     * @param certAlias
     * @return
     */
    private FileData getSignatureImage(ItemCollection doc) {

        FileData fileData = doc.getFileData("signature.jpg");
        if (fileData != null && fileData.getContent() != null && fileData.getContent().length > 0) {
            // we found a signature image!
            return fileData;
        }

        return null;
    }

}