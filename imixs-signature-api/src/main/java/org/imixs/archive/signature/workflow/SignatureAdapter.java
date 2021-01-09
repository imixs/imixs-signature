package org.imixs.archive.signature.workflow;

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
        
   }
 * </pre>
 * 
 * @version 1.0
 * @author rsoika
 */
public class SignatureAdapter implements SignalAdapter {

    public static final String PDF_REGEX = "^.+\\.([pP][dD][fF])$";

    @Inject
    WorkflowService workflowService;

    @Inject
    DocumentService documentService;

    @Inject
    ClientHelper clientHelper;

    @Inject
    SnapshotService snapshotService;

    private static Logger logger = Logger.getLogger(SignatureAdapter.class.getName());

    /**
     * This method posts a text from an attachment to the Imixs-ML Analyse service
     * endpoint
     */
    @Override
    public ItemCollection execute(ItemCollection document, ItemCollection event) throws AdapterException {

        String file_pattern = PDF_REGEX;

        DocumentClient documentClient = clientHelper.initDocumentClient();

        try {
            // do we have file attachments?
            List<String> fileNames = document.getFileNames();
            if (fileNames.size() > 0) {

                ItemCollection signingWorkitem = new ItemCollection();
                // read signature options
                ItemCollection evalItemCollection = workflowService.evalWorkflowResult(event, "signature", document,
                        false);
                if (evalItemCollection != null) {
                    if (evalItemCollection.hasItem("autocreate")) {
                        signingWorkitem.setItemValue("autocreate",
                                evalItemCollection.getItemValueBoolean("autocreate"));
                    }
                    if (evalItemCollection.hasItem("rootsignature")) {
                        signingWorkitem.setItemValue("rootsignature",
                                evalItemCollection.getItemValueBoolean("rootsignature"));
                    }
                    if (evalItemCollection.hasItem("filepattern")) {
                        signingWorkitem.setItemValue("filepattern",
                                evalItemCollection.getItemValueString("filepattern"));
                    }

                    if (evalItemCollection.hasItem("position-x")) {
                        signingWorkitem.setItemValue("position-x", evalItemCollection.getItemValueFloat("position-x"));
                    }
                    if (evalItemCollection.hasItem("position-y")) {
                        signingWorkitem.setItemValue("position-y", evalItemCollection.getItemValueFloat("position-y"));
                    }
                    if (evalItemCollection.hasItem("dimension-w")) {
                        signingWorkitem.setItemValue("dimension-w",
                                evalItemCollection.getItemValueFloat("dimension-w"));
                    }
                    if (evalItemCollection.hasItem("dimension-h")) {
                        signingWorkitem.setItemValue("dimension-h",
                                evalItemCollection.getItemValueFloat("dimension-h"));
                    }
                }

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

                        String certAlias = workflowService.getUserName();
                        FileData fileDataSignature = loadSignatureImageFromProfile(certAlias);
                        if (fileDataSignature != null) {

                            signingWorkitem.addFileData(fileDataSignature);

                        }

                        XMLDocument xmlDataCollection = XMLDocumentAdapter.getDocument(signingWorkitem);
                        // sign pdf....
                        XMLDataCollection resultDoc = documentClient.postXMLDocument("sign", xmlDataCollection);

                        if (resultDoc != null && resultDoc.getDocument().length > 0) {
                            ItemCollection signedWorkitem = XMLDocumentAdapter.putDocument(resultDoc.getDocument()[0]);
                            // ad the signed pdf file to the workitem
                            List<FileData> fileDataList = signedWorkitem.getFileData();
                            for (FileData signedFileData : fileDataList) {
                                document.addFileData(signedFileData);
                            }
                            // force overwriting content...
                            document.appendItemValue(SnapshotService.ITEM_SNAPSHOT_OVERWRITEFILECONTENT, fileName);
                        }

                        logger.info("......signing " + fileName + " completed!");
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