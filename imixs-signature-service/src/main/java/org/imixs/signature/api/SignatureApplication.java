package org.imixs.signature.api;

import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;

@ApplicationPath("api")
public class SignatureApplication extends Application {

    public static final String ITEM_WORKFLOW_ENDPOINT = "workflow.endpoint";
    public static final String ITEM_WORKFLOW_USER = "workflow.userid";
    public static final String ITEM_WORKFLOW_PASSWORD = "workflow.password";
    public static final String ITEM_WORKFLOW_QUERY = "workflow.query";
    public static final String ITEM_WORKFLOW_PAGEINDEX = "workflow.pageindex";
    public static final String ITEM_WORKFLOW_PAGESIZE = "workflow.pagesize";
    public static final String ITEM_ENTITIES = "workflow.entities";
    public static final String ITEM_LOCALES = "workflow.locale";
    public static final String ITEM_TIKA_OPTIONS = "tika.options";
    public static final String ITEM_TIKA_OCR_MODE = "tika.ocrmode";
    public static final String ITEM_ML_TRAINING_ENDPOINT = "ml.training.endpoint";
    public static final String ITEM_ML_ANALYSE_ENDPOINT = "ml.analyse.endpoint";
    public static final String ITEM_ML_TRAINING_QUALITYLEVEL = "ml.training.quality";

  
}