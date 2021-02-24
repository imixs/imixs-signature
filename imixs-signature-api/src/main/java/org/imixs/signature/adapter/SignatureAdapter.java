package org.imixs.signature.adapter;

import java.util.List;
import java.util.logging.Logger;
import java.util.regex.Pattern;

import javax.inject.Inject;

import org.imixs.archive.core.SnapshotService;
import org.imixs.melman.DocumentClient;
import org.imixs.melman.RestAPIException;
import org.imixs.workflow.FileData;
import org.imixs.workflow.ItemCollection;
import org.imixs.workflow.SignalAdapter;
import org.imixs.workflow.WorkflowKernel;
import org.imixs.workflow.engine.DocumentService;
import org.imixs.workflow.engine.WorkflowService;
import org.imixs.workflow.exceptions.AdapterException;
import org.imixs.workflow.exceptions.PluginException;
import org.imixs.workflow.exceptions.ProcessingErrorException;
import org.imixs.workflow.exceptions.QueryException;
import org.imixs.workflow.xml.XMLDataCollection;
import org.imixs.workflow.xml.XMLDocument;
import org.imixs.workflow.xml.XMLDocumentAdapter;

/**
 * The SignatureAdapter signs a PDF document.
 * <p>
 * The adapter creates a digital signature with the certificate associated with
 * the current user name by sending the pdf document to the Imixs
 * Signatur-Service.
 * <p>
 * 
 * <pre>
 * {@code
        <signature name="autocreate">true</signature>
        <signature name="rootsignature">true</signature>
        <signature name="filepattern">order.pdf</signature>
        <signature name="position-x">50</signature>
        <signature name="position-y">650</signature>
        <signature name="dimension-w">170</signature>
        <signature name="dimension-h">50</signature>
        <signature name="verticalalignment">true</signature>
        
   }
 * </pre>
 * 
 * @version 1.0
 * @author rsoika
 */
public class SignatureAdapter implements SignalAdapter {

    public static final String PDF_REGEX = "^.+\\.([pP][dD][fF])$";

    public static final String OPTION_AUTOCREATE = "autocreate";
    public static final String OPTION_ROOTSIGNATURE = "rootsignature";
    public static final String OPTION_POSITION_X = "position-x";
    public static final String OPTION_POSITION_Y = "position-y";
    public static final String OPTION_DIMENSION_W = "dimension-w";
    public static final String OPTION_DIMENSION_H = "dimension-h";
    public static final String OPTION_VERTICAL_ALIGNMENT = "verticalAlignment";
    public static final String OPTION_AUTO_ALIGNMENT = "autoAlignment";
    public static final String OPTION_PAGE = "page";
    public static final String OPTION_FILEPATTERN = "filepattern";

    @Inject
    WorkflowService workflowService;

    @Inject
    DocumentService documentService;

    @Inject
    DocumentClientFactory clientHelper;

    @Inject
    SnapshotService snapshotService;

    @Inject
    X509ProfileHandler x509ProfileHandler;

    private static Logger logger = Logger.getLogger(SignatureAdapter.class.getName());

    /**
     * This method posts a text from an attachment to the Imixs-ML Analyse service
     * endpoint
     */
    @Override
    public ItemCollection execute(ItemCollection document, ItemCollection event) throws AdapterException {

        String file_pattern = PDF_REGEX;

        DocumentClient documentClient = clientHelper.initDocumentClient();

        String certAlias = workflowService.getUserName();

        try {
            // do we have file attachments?
            List<String> fileNames = document.getFileNames();
            if (fileNames.size() > 0) {

                ItemCollection signingWorkitem = new ItemCollection();
                signingWorkitem.setItemValue(WorkflowKernel.WORKFLOWSTATUS,
                        document.getItemValueString(WorkflowKernel.WORKFLOWSTATUS));
                // read signature options
                ItemCollection evalItemCollection = workflowService.evalWorkflowResult(event, "signature", document,
                        false);
                if (evalItemCollection != null) {
                    if (evalItemCollection.hasItem(OPTION_AUTOCREATE)) {
                        signingWorkitem.setItemValue(OPTION_AUTOCREATE,
                                evalItemCollection.getItemValueBoolean(OPTION_AUTOCREATE));
                    }
                    if (evalItemCollection.hasItem(OPTION_ROOTSIGNATURE)) {
                        signingWorkitem.setItemValue(OPTION_ROOTSIGNATURE,
                                evalItemCollection.getItemValueBoolean(OPTION_ROOTSIGNATURE));
                    }
                    if (evalItemCollection.hasItem(OPTION_FILEPATTERN)) {
                        signingWorkitem.setItemValue(OPTION_FILEPATTERN,
                                evalItemCollection.getItemValueString(OPTION_FILEPATTERN));
                    }

                    // page and position for visual signature
                    if (evalItemCollection.hasItem(OPTION_PAGE)) {
                        signingWorkitem.setItemValue(OPTION_PAGE, evalItemCollection.getItemValueInteger(OPTION_PAGE));
                    }
                    if (evalItemCollection.hasItem(OPTION_POSITION_X)) {
                        signingWorkitem.setItemValue(OPTION_POSITION_X,
                                evalItemCollection.getItemValueFloat(OPTION_POSITION_X));
                    }
                    if (evalItemCollection.hasItem(OPTION_POSITION_Y)) {
                        signingWorkitem.setItemValue(OPTION_POSITION_Y,
                                evalItemCollection.getItemValueFloat(OPTION_POSITION_Y));
                    }
                    if (evalItemCollection.hasItem(OPTION_DIMENSION_W)) {
                        signingWorkitem.setItemValue(OPTION_DIMENSION_W,
                                evalItemCollection.getItemValueFloat(OPTION_DIMENSION_W));
                    }
                    if (evalItemCollection.hasItem(OPTION_DIMENSION_H)) {
                        signingWorkitem.setItemValue(OPTION_DIMENSION_H,
                                evalItemCollection.getItemValueFloat(OPTION_DIMENSION_H));
                    }
                    if (evalItemCollection.hasItem(OPTION_VERTICAL_ALIGNMENT)) {
                        signingWorkitem.setItemValue(OPTION_VERTICAL_ALIGNMENT,
                                evalItemCollection.getItemValueBoolean(OPTION_VERTICAL_ALIGNMENT));
                    }
                    if (evalItemCollection.hasItem(OPTION_AUTO_ALIGNMENT)) {
                        signingWorkitem.setItemValue(OPTION_AUTO_ALIGNMENT,
                                evalItemCollection.getItemValueBoolean(OPTION_AUTO_ALIGNMENT));
                    }
                }
                // lookup the x509 data form the x509ProfileHandler
                ItemCollection x509Profile = x509ProfileHandler.findX509Profile(certAlias);
                // copy x509 attributes....
                if (x509Profile != null) {
                    signingWorkitem.setItemValue("x509.cn", x509Profile.getItemValue("txtusername"));
                    signingWorkitem.setItemValue("x509.o", x509Profile.getItemValue("x509.o"));
                    signingWorkitem.setItemValue("x509.ou", x509Profile.getItemValue("x509.ou"));
                    signingWorkitem.setItemValue("x509.city", x509Profile.getItemValue("x509.city"));
                    signingWorkitem.setItemValue("x509.state", x509Profile.getItemValue("x509.state"));
                    signingWorkitem.setItemValue("x509.country", x509Profile.getItemValue("x509.country"));
                }

                // set signature.count
                signingWorkitem.setItemValue("signature.count", document.getItemValue("signature.count"));

                // do we have files matching the file pattern?
                Pattern filePatternMatcher = Pattern.compile(file_pattern);
                for (String fileName : fileNames) {
                    // did the file math our file pattern?
                    if (filePatternMatcher.matcher(fileName).find()) {
                        // yes! start signing....

                        // read the file data...
                        FileData fileData = document.getFileData(fileName);
                        byte[] sourceContent = fileData.getContent();
                        if (sourceContent.length == 0) {
                            // load from snapshot
                            ItemCollection snapshot = snapshotService.findSnapshot(document);
                            fileData = snapshot.getFileData(fileName);
                            sourceContent = fileData.getContent();
                        }

                        signingWorkitem.addFileData(fileData);

                        signingWorkitem.setItemValue("certAlias", certAlias);
                        FileData fileDataSignature = loadSignatureImageFromProfile(certAlias);
                        if (fileDataSignature != null) {
                            signingWorkitem.addFileData(fileDataSignature);
                        } else {
                            // print a warning if no signature image exist...
                            if (!signingWorkitem.getItemValueBoolean(OPTION_ROOTSIGNATURE)) {
                                logger.warning("Missing signature image for profile '" + certAlias + "'!");
                            }
                        }

                        XMLDocument xmlDataCollection = XMLDocumentAdapter.getDocument(signingWorkitem);
                        // sign pdf....
                        XMLDataCollection signedXMLData = documentClient.postXMLDocument("sign", xmlDataCollection);

                        if (signedXMLData != null && signedXMLData.getDocument().length > 0) {
                            ItemCollection signedWorkitem = XMLDocumentAdapter
                                    .putDocument(signedXMLData.getDocument()[0]);
                            // ad the signed pdf file to the workitem
                            List<FileData> fileDataList = signedWorkitem.getFileData();
                            for (FileData signedFileData : fileDataList) {
                                document.addFileData(signedFileData);
                            }
                            // force overwriting content...
                            document.appendItemValue(SnapshotService.ITEM_SNAPSHOT_OVERWRITEFILECONTENT, fileName);

                            // update signature.count
                            document.setItemValue("signature.count", signedWorkitem.getItemValue("signature.count"));

                        }

                        logger.info("......signing " + fileName + " successful.");
                    }
                }
            }
        } catch (PluginException | RestAPIException e) {
            throw new ProcessingErrorException(this.getClass().getSimpleName(), "SIGNING_ERROR", e.getMessage(), e);
        }

        return document;
    }

    /**
     * This helper method tries to load a signature image form the current user
     * profile the expected file name is 'signature.jpg'
     * 
     * @param certAlias
     * @return
     */
    private FileData loadSignatureImageFromProfile(String certAlias) {

        // test if we have a signatrue image in the user profile...
        List<ItemCollection> userProfileList;
        try {
            userProfileList = documentService.find("type:profile AND txtname:" + certAlias, 1, 0);

            if (userProfileList.size() > 0) {
                ItemCollection profile = userProfileList.get(0);

                FileData fileData = snapshotService.getWorkItemFile(profile.getUniqueID(), "signature.jpg");
                if (fileData==null) {
                    // try .png
                    fileData = snapshotService.getWorkItemFile(profile.getUniqueID(), "signature.png");
                }
                if (fileData==null) {
                    // try .gif
                    fileData = snapshotService.getWorkItemFile(profile.getUniqueID(), "signature.gif");
                }
                if (fileData != null && fileData.getContent() != null && fileData.getContent().length > 0) {
                    // we found a signature image!
                    return fileData;
                }
            }

        } catch (QueryException e) {
            logger.warning("Failed to load signature image from profile : " + e.getMessage());
        }

        return null;
    }

}