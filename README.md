# Imixs-Signature 

The *Imixs-Signature* provides a service to sign PDF documents attached to a Imixs-Workflow workitem during the workflow processing life-cycle. 

The signing process did not only sign a PDF document with a X509 certificate, but also adds a visual element into the PDF document linked to the signature. This gives the user the possibility to visually recognize the signature and control the validity of the document based on the embedded digital signature.

<img src="docs/imixs-signature-example-001.png">


The implementation is based on the Apache project [PDFBox](https://pdfbox.apache.org/) and the Crypto-API [Bouncycastle](http://bouncycastle.org/). 

## Installation

The *Imixs-Signature-Service* can be started as a Docker container. See the following example of a docker-compose stack definition:



	  office:
	    image: imixs/imixs-office-workflow:latest
	    environment:
	      ....
	      SIGNATURE_SERVICE_ENDPOINT: "http://imixssignature:8080/api"
	    ports:
	      - "8080:8080"
	
		...	
	
	  imixssignature:
	    image: imixs/imixs-signature-service
	    environment:
	      SIGNATURE_KEYSTORE_PATH: "/opt/keys/imixs.jks"
	      SIGNATURE_KEYSTORE_PASSWORD: "123456" 
	      SIGNATURE_KEYSTORE_TYPE: "PKCS12"
	      SIGNATURE_ROOTCERT_ALIAS: "imixs.com"
	      SIGNATURE_ROOTCERT_PASSWORD: "123456" 
	    ports:
	      - "8082:8080"
	    volumes:
	      - ./keys:/opt/keys/

The Signature service is defined by the following environment parameters:


| Parameter                    | Description                        |
| ---------------------------- |----------------------------------- |
| SIGNATURE_KEYSTORE_PATH      | filepath to the java keystore file |
| SIGNATURE_KEYSTORE_PASSWORD  | password for the java keystore     |
| SIGNATURE_KEYSTORE_TYPE      | keystore type (PKSC12)             |
| SIGNATURE_ROOTCERT_ALIAS     | root certificate alias             |
| SIGNATURE_ROOTCERT_PASSWORD  | root certificate password          |

The next section describes how the java keystore is used by the signature service to sign documents.



## Signing a PDF Document

To sign a PDF document, a signature based on a X509 certificate is created based on the content of the PDF document. The signature is written back into a new signed version of the origin document. The X509 certificates are stored in a java keystore. 

### The Keystore

The *Imixs-Archive Signature API* expects a keystore containing certificates and key pairs to create a signature. The keystore can be managed with the java command line tool *keytool*. The Keytool is provided with standard JDK, so usual no additional installation is necessary. 

A Keystore can keep several keys pairs, each of them is created with a proper alias to be identified by the *Imixs-Archive Signature API*. Any kind of X509 certificate can be used in the signing process and also certificate chains are supported. The keystore is independent form this API.

To create a self-signed certificate with the alias 'imixs' run:

	$ keytool -genkey -alias imixs -keyalg RSA -sigalg SHA256withRSA -keysize 2048 -validity 3650 -keystore imixs.jks

In this example, a 2048-bit RSA key pair valid for 365 days under the specified alias 'imixs' is generated. 
The key pair is added into the keystore file with default ‘.jks’ extension.
The keystore expects a password. This password will be used later by the *Imixs-Archive Signature API* to open the keystore. 
 Note: the certificates are usually stored with an empty password. You can find more details about how to manage the keystore [here](docs/README.md). 


 
### The PDF Signing Service

The *Imixs-Archive Signature API* provides a signing service to sign PDF documents with a X509 certificate stored in a java keystore. The service can be configured by the following environment variables:

 * SIGNATURE_KEYSTORE_PATH - path to a java keystore containing valid certificates and private keys
 * SIGNATURE_KEYSTORE_PASSWORD - the password used to unlock the keystore
 * SIGNATURE_KEYSTORE_TYPE - keystore file extension (defautl =.jks)
 * SIGNATURE_TSA_URL - an optional Time Stamping Authority (TSA) server
 * SIGNATURE_ROOTCERT_ALIAS - the root cert alias
 * SIGNATURE_ROOTCERT_PASSWORD - the root cert password (optional)

The service adds a didgital signature to a new version of a given PDF document and also creates a visual element linked with the signature.
The implementation to sign a PDF document is based on the open source library [PDFBox](https://github.com/apache/pdfbox) and the crypto API [Bouncycastle](http://bouncycastle.org/). General examples how to sign a PDF document with PDFBox including visible signatures can be found [here](https://github.com/apache/pdfbox/tree/trunk/examples/src/main/java/org/apache/pdfbox/examples/signature). 
An introduction how signing PDF files works can also be found [here](https://jvmfy.com/2018/11/17/how-to-digitally-sign-pdf-files/).

### The Imixs-Signature API

The *Imixs-Signature-API* provides a Rest Client to connect the Imixs-Workflow engine with the Imixs-Signature-Service. The API can be added to the Imixs-Workflow engine with the following maven dependencies:


		<!-- Imixs Signature Feature -->
		<dependency>
			<groupId>org.imixs.workflow</groupId>
			<artifactId>imixs-signature-api</artifactId>
			<version>${org.imixs.signature.version}</version>
			<scope>compile</scope>
		</dependency>


By defining the environment variable 'SIGNATURE_SERVICE_ENDPOINT' the workflow engine can connect to the signature service to sign PDF documents.


	# Signature
	SIGNATURE_SERVICE_ENDPOINT: "http://imixssignature:8080/api"
	
The API provides an Adapter class to be used in a Imixs BPMN model. The adaper is responsible to send a PDF document to the Imixs-Signature-Service for a signing request. 	
	
### The Signature Adapter

The SignatureAdapter integrates the *Imixs-Archive Signature API* into a business process based on a Imixs BPMN model. The adapter automatically signs attached PDF documents. 

	org.imixs.signature.adapter.SignatureAdapter
	
The SignatureAdapter does throw a PluginException in case not certificate for the current user was not found by the CA Service. The CAService can be used to generate user certificates	based on a root certificate. 

#### Configuration
The adapter creates a new  certificate (autocreate=true) or signs the document with the root certificate if no user certificate exists (rootsignature=true)


**filepattern**

A  regular expression to filter the attachments do be signed by the plugin. 

	<signature name="filepattern">order.pdf</signature>


If no file pattern is set, only PDF files will be signed 

	(^.+\\.([pP][dD][fF])$).

The following example will sign all pdf files with the sufix 'order.pdf'

	 (^.+order.pdf)

You can find general details about how to use an Adapter with Imixs-Workflow [here](https://www.imixs.org/doc/core/adapter-api.html).


**rootsignature**

The document will be signed with the root certificate.

	<signature name="rootsignature">true</signature>

If not set, a signature based on the current user will be generated. 

**autocreate**

If autocreate=true than in case no certificate for the current user exists, the SignatureAdaper will create a certificate on the fly.

	<signature name="autocreate">true</signature>

**Signature Positon**

The visual signature can be positioned by the following optional parameters:

    <signature name="position-x">50</signature>
    <signature name="position-y">650</signature>
    <signature name="dimension-w">170</signature>
    <signature name="dimension-h">50</signature>
    <signature name="page">1</signature>
    

In case of multiple signatures the alignment can be set to horizontal (default) or vertical. This auto-alignment option can be deactivated 

    <signature name="verticalAlignment">true</signature>
    <signature name="autoAlignment">true</signature>

	
## The CA Service
	
The CAService provides methods to managed X509Certificates stored in a keystore. The certificates managed by this service
are  used for  digital Signature only. Certificates are singed based on an existing root or intermediate Certificate stored in a keystore.

The Certificates generated by this service have empty passwords and are protected by the keystore. Optinal the root certificate can be password protected. Certificates managed by this service should never be published and should be used for digital signatures only

If a for a given alias not certificate is yet stored in the keystore, the CAService automatically creates a new X509 certificated with the class X509CertificateGenerator. This generator can be used independently from this API. There are also JUnit tests available demonstrating the core functionality. 


### X509 Attributes

The CAService expects an optional profile document containing the following X509 items (all items are optional)

 - x509.cn - common name
 - x509.o  - organisation 
 - x509.ou - list of optional organisation units
 - x509.city - City
 - x509.state - State
 - x509.country - Country


### The X509ProfileHandler

The *X509ProfileHandler* is a CDI bean to lookup the X509 profile data for a  given alias name. The *X509ProfileHandler* is called by the *CAService* during the generation of a new X509 certificate. 

The default lucene query to lookup the data is:

	(type:"profile") AND (name:"?" OR txtname:"?")

The query can be configured by the environment variable SIGNATURE_X509_PROFILE_QUERY.

The CDI bean can be overwritten with an alternative application specific implementation. This can be useful in case the X509 data exist in an external data source like a LDAP directory to be used to  lookup the X509 data.

In Imixs-Office-Workflow a corresponding UI feature within the user management can be activated with the property *profile.x509*

	profile.x509=true