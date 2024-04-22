package exampleXAdES_T_Imp;

//original reference : https://community.sap.com/t5/technology-blogs-by-members/digital-signing-xml-s-in-sap-pi-with-xades-extensions/ba-p/13380985
import java.io.BufferedReader;
import java.io.Console;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.security.KeyStore.PasswordProtection;
import java.util.ArrayList;
import java.util.List;
import java.io.IOException;	//added for troubleshooting
//import com.sap.aii.mapping.api.AbstractTransformation;
//import com.sap.aii.mapping.api.StreamTransformationException;
//import com.sap.aii.mapping.api.TransformationInput;
//import com.sap.aii.mapping.api.TransformationOutput;

//original import statement in the reference for DSS API by European
import eu.europa.esig.dss.model.DSSDocument;						//import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;				//import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.model.InMemoryDocument;					//import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.enumerations.SignatureLevel;				//import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;			//import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.model.SignatureValue;						//import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;							//import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.token.AbstractSignatureTokenConnection;	// ..somehow maven repo did not download this, manually inserted dss-token
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;					// ..somehow maven repo did not download this, manually inserted dss-token
import eu.europa.esig.dss.token.Pkcs12SignatureToken;				//added, due to incompatibility with self signed sample
//import eu.europa.esig.dss.token.JKSSignatureToken;				// ..somehow maven repo did not download this, manually inserted; incompatible w/ self-signed sample
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.model.x509.CertificateToken;				//import eu.europa.esig.dss.x509.CertificateToken;	
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

//test import for compliance to IRB
import eu.europa.esig.dss.xades.XAdESSignatureParameters.XPathElementPlacement;

//for XAdES-T
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.x509.tsp.KeyEntityTSPSource;	//test
import javax.xml.crypto.dsig.CanonicalizationMethod;

import java.io.File;
import java.nio.file.Files;
import java.security.KeyStore;

import eu.europa.esig.dss.xades.reference.CanonicalizationTransform;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.DSSTransform;
import eu.europa.esig.dss.xades.reference.XPathTransform;
import eu.europa.esig.dss.xml.common.definition.DSSNamespace;
import eu.europa.esig.dss.xml.utils.DomUtils;
//additional jar need to be configured into build path sun istack commons, jakarta xml bind, sl4j, glassfish runtime and core, jakarta activation, dss-utils-apache-commons, commons-codec 1.15, apache-commons-lang3, bouncy castle, apache xml sec, commons-io
//commons-collections4, apache hc client5, core5, core5/h2,
import eu.europa.esig.dss.xml.utils.XMLCanonicalizer;

public class exampleXAdES_T_Imp {
/*
	public TransformationOutput transformationOutput;
	public OutputStream out;
	String temp = null;*/

	//@Override /**probably version difference, uncomment if override is required
	/*
	public void transform(TransformationInput transformationInput, TransformationOutput transformationOutput)
	throws StreamTransformationException {
		try {
			/*Getting Input Stream and writing out as Output in XML*/
			//String InputXML = "";
			//String line = "";
			/*Digital Signing Starts from here*/
			// this file holds the signing key
			/*Below are three parameterised mapping variables used to get 3 inputs 
	    	1. JKS private Key file location 
	    	//example input path: /sapmnt/PID/DigitalSignatureTest/
	    	2. JKS private key File Name and 
	    	3. JKS private key password at runtime from ICO.*/  /*<<----remove this to uncomment! 
			String PrivateKeyPath = transformationInput.getInputParameters().getString("\"C:\\Users\\User\\Desktop\\pk\"");
			String PrivateKeyName = transformationInput.getInputParameters().getString("cert");
			PasswordProtection keystorePassword = new PasswordProtection(transformationInput.getInputParameters().getString("").toCharArray());
			String keystoreFile = PrivateKeyPath + PrivateKeyName;
			DSSDocument signDocument;
			InputStream ins = transformationInput.getInputPayload().getInputStream();
			BufferedReader br = new BufferedReader(new InputStreamReader(ins));

			while ((line = br.readLine()) != null)
				InputXML += line;
			br.close();

	      signDocument = this.signDocument(InputXML, keystoreFile, keystorePassword);
	      transformationOutput.getOutputPayload().getOutputStream().write(((InMemoryDocument) signDocument).getBytes());
		} catch (Exception exception) {
			throw new StreamTransformationException(exception.toString());
		}
	}*/
	
	public exampleXAdES_T_Imp(){}

	private class customXPathTransform extends XPathTransform{
		customXPathTransform(DSSNamespace ns, String algo, String xpath)
		{
			super(ns,algo,xpath);
		}
	}
	
	//modded to allow console testing
	public byte[] transform() throws Exception {
		try {
			String InputXML = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"no\"?><Invoice xmlns=\"urn:oasis:names:specification:ubl:schema:xsd:Invoice-2\" xmlns:cac=\"urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2\" xmlns:cbc=\"urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2\" xmlns:ext=\"urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2\"><cbc:ID>INV12345</cbc:ID><cbc:IssueDate>2017-11-26</cbc:IssueDate><cbc:IssueTime>15:30:00Z</cbc:IssueTime><cbc:InvoiceTypeCode listVersionID=\"1.0\">01</cbc:InvoiceTypeCode><cbc:DocumentCurrencyCode>MYR</cbc:DocumentCurrencyCode><cac:InvoicePeriod><cbc:StartDate>2017-11-26</cbc:StartDate><cbc:EndDate>2017-11-30</cbc:EndDate><cbc:Description>Monthly</cbc:Description></cac:InvoicePeriod><cac:BillingReference><cac:InvoiceDocumentReference><cbc:ID>INV54321</cbc:ID><cbc:UUID>F9D425P6DS7D8IU</cbc:UUID></cac:InvoiceDocumentReference></cac:BillingReference><cac:BillingReference><cac:AdditionalDocumentReference><cbc:ID>L1</cbc:ID></cac:AdditionalDocumentReference></cac:BillingReference><cac:AdditionalDocumentReference><cbc:ID>L1</cbc:ID><cbc:DocumentType>CustomsImportForm</cbc:DocumentType></cac:AdditionalDocumentReference><cac:AdditionalDocumentReference><cbc:ID>FTA</cbc:ID><cbc:DocumentType>FreeTradeAgreement</cbc:DocumentType><cbc:DocumentDescription>Sample Description</cbc:DocumentDescription></cac:AdditionalDocumentReference><cac:AdditionalDocumentReference><cbc:ID>L1</cbc:ID><cbc:DocumentType>K2</cbc:DocumentType></cac:AdditionalDocumentReference><cac:AdditionalDocumentReference><cbc:ID>L1</cbc:ID></cac:AdditionalDocumentReference><cac:AccountingSupplierParty><cbc:AdditionalAccountID schemeAgencyName=\"CertEX\"/><cac:Party><cbc:IndustryClassificationCode name=\"Growing of maize\">01111</cbc:IndustryClassificationCode><cac:PartyIdentification><cbc:ID schemeID=\"TIN\">C948329382</cbc:ID></cac:PartyIdentification><cac:PartyIdentification><cbc:ID schemeID=\"NRIC\">123456789012</cbc:ID></cac:PartyIdentification><cac:PostalAddress><cbc:CityName>Cyberjaya</cbc:CityName><cbc:PostalZone>63000</cbc:PostalZone><cbc:CountrySubentityCode>Selangor</cbc:CountrySubentityCode><cac:AddressLine><cbc:Line>Persiaran Rimba Permai</cbc:Line></cac:AddressLine><cac:AddressLine><cbc:Line>Cyber 8</cbc:Line></cac:AddressLine><cac:AddressLine><cbc:Line>63000 Cyberjaya</cbc:Line></cac:AddressLine><cac:Country><cbc:IdentificationCode listAgencyID=\"6\" listID=\"ISO3166-1\">MYS</cbc:IdentificationCode></cac:Country></cac:PostalAddress><cac:PartyLegalEntity><cbc:RegistrationName>AMS Setia Jaya Sdn. Bhd.</cbc:RegistrationName></cac:PartyLegalEntity><cac:Contact><cbc:Telephone>+96-9876543210</cbc:Telephone><cbc:ElectronicMail>xyz@test.com</cbc:ElectronicMail></cac:Contact></cac:Party></cac:AccountingSupplierParty><cac:AccountingCustomerParty><cac:Party><cac:PartyIdentification><cbc:ID schemeID=\"TIN\">C948329382</cbc:ID></cac:PartyIdentification><cac:PartyIdentification><cbc:ID schemeID=\"NRIC\">L1</cbc:ID></cac:PartyIdentification><cac:PostalAddress><cbc:CityName>Kuala Lumpur</cbc:CityName><cbc:PostalZone>50200</cbc:PostalZone><cbc:CountrySubentityCode>Wilayah Persekutuan</cbc:CountrySubentityCode><cac:AddressLine><cbc:Line>Lot 5 08</cbc:Line></cac:AddressLine><cac:AddressLine><cbc:Line>5th Floor</cbc:Line></cac:AddressLine><cac:AddressLine><cbc:Line>Wisma Cosway Jalan Raja Chulan</cbc:Line></cac:AddressLine><cac:Country><cbc:IdentificationCode listAgencyID=\"6\" listID=\"ISO3166-1\">MYS</cbc:IdentificationCode></cac:Country></cac:PostalAddress><cac:PartyLegalEntity><cbc:RegistrationName>Chuan Sin Sdn. Bhd.</cbc:RegistrationName></cac:PartyLegalEntity><cac:Contact><cbc:Telephone>+96-9876543210</cbc:Telephone><cbc:ElectronicMail>xyz@test.com</cbc:ElectronicMail></cac:Contact></cac:Party></cac:AccountingCustomerParty><cac:PaymentMeans><cbc:PaymentMeansCode>31</cbc:PaymentMeansCode><cac:PayeeFinancialAccount><cbc:ID>L1</cbc:ID></cac:PayeeFinancialAccount></cac:PaymentMeans><cac:PaymentTerms><cbc:Note>Penalty percentage 10% from due date</cbc:Note></cac:PaymentTerms><cac:PrepaidPayment><cbc:ID>L1</cbc:ID><cbc:PaidAmount currencyID=\"MYR\">1.0</cbc:PaidAmount><cbc:PaidDate>2000-01-01</cbc:PaidDate><cbc:PaidTime>12:00:00</cbc:PaidTime></cac:PrepaidPayment><cac:AllowanceCharge><cbc:ChargeIndicator>false</cbc:ChargeIndicator><cbc:AllowanceChargeReason>Sample Description</cbc:AllowanceChargeReason><cbc:Amount currencyID=\"MYR\">100</cbc:Amount></cac:AllowanceCharge><cac:AllowanceCharge><cbc:ChargeIndicator>true</cbc:ChargeIndicator><cbc:AllowanceChargeReason>Sample Description</cbc:AllowanceChargeReason><cbc:Amount currencyID=\"MYR\">100</cbc:Amount></cac:AllowanceCharge><cac:TaxTotal><cbc:TaxAmount currencyID=\"MYR\">60.00</cbc:TaxAmount><cac:TaxSubtotal><cbc:TaxableAmount currencyID=\"MYR\">60.00</cbc:TaxableAmount><cbc:TaxAmount currencyID=\"MYR\">1000.00</cbc:TaxAmount><cac:TaxCategory><cbc:ID>01</cbc:ID><cac:TaxScheme><cbc:ID schemeAgencyID=\"6\" schemeID=\"UN/ECE 5153\">OTH</cbc:ID></cac:TaxScheme></cac:TaxCategory></cac:TaxSubtotal></cac:TaxTotal><cac:LegalMonetaryTotal><cbc:LineExtensionAmount currencyID=\"MYR\">1436.5</cbc:LineExtensionAmount><cbc:TaxExclusiveAmount currencyID=\"MYR\">1436.5</cbc:TaxExclusiveAmount><cbc:TaxInclusiveAmount currencyID=\"MYR\">1436.5</cbc:TaxInclusiveAmount><cbc:AllowanceTotalAmount currencyID=\"MYR\">1436.5</cbc:AllowanceTotalAmount><cbc:ChargeTotalAmount currencyID=\"MYR\">1436.5</cbc:ChargeTotalAmount><cbc:PayableRoundingAmount currencyID=\"MYR\">0.30</cbc:PayableRoundingAmount><cbc:PayableAmount currencyID=\"MYR\">1436.5</cbc:PayableAmount></cac:LegalMonetaryTotal><cac:InvoiceLine><cbc:ID>1234</cbc:ID><cbc:InvoicedQuantity unitCode=\"C62\">1</cbc:InvoicedQuantity><cbc:LineExtensionAmount currencyID=\"MYR\">1436.5</cbc:LineExtensionAmount><cac:AllowanceCharge><cbc:ChargeIndicator>false</cbc:ChargeIndicator><cbc:AllowanceChargeReason>Sample Description</cbc:AllowanceChargeReason><cbc:MultiplierFactorNumeric>0.15</cbc:MultiplierFactorNumeric><cbc:Amount currencyID=\"MYR\">100</cbc:Amount></cac:AllowanceCharge><cac:AllowanceCharge><cbc:ChargeIndicator>true</cbc:ChargeIndicator><cbc:AllowanceChargeReason>Sample Description</cbc:AllowanceChargeReason><cbc:MultiplierFactorNumeric>0.10</cbc:MultiplierFactorNumeric><cbc:Amount currencyID=\"MYR\">100</cbc:Amount></cac:AllowanceCharge><cac:TaxTotal><cbc:TaxAmount currencyID=\"MYR\">60.00</cbc:TaxAmount><cac:TaxSubtotal><cbc:TaxableAmount currencyID=\"MYR\">1000.00</cbc:TaxableAmount><cbc:TaxAmount currencyID=\"MYR\">60.00</cbc:TaxAmount><cac:TaxCategory><cbc:ID>01</cbc:ID><cbc:Percent>6.00</cbc:Percent><cac:TaxScheme><cbc:ID schemeAgencyID=\"6\" schemeID=\"UN/ECE 5153\">OTH</cbc:ID></cac:TaxScheme></cac:TaxCategory></cac:TaxSubtotal></cac:TaxTotal><cac:Item><cbc:Description>Laptop Peripherals</cbc:Description><cac:OriginCountry><cbc:IdentificationCode>MYS</cbc:IdentificationCode></cac:OriginCountry><cac:CommodityClassification><cbc:ItemClassificationCode listID=\"PTC\">12344321</cbc:ItemClassificationCode></cac:CommodityClassification><cac:CommodityClassification><cbc:ItemClassificationCode listID=\"CLASS\">023</cbc:ItemClassificationCode></cac:CommodityClassification><cac:CommodityClassification><cbc:ItemClassificationCode listID=\"CLASS\">011</cbc:ItemClassificationCode></cac:CommodityClassification></cac:Item><cac:Price><cbc:PriceAmount currencyID=\"MYR\">17</cbc:PriceAmount></cac:Price><cac:ItemPriceExtension><cbc:Amount currencyID=\"MYR\">100</cbc:Amount></cac:ItemPriceExtension></cac:InvoiceLine></Invoice>";
			//String InputXML = "<?xml version=\"1.0\" encoding=\"UTF-8\" ?><family><wet><worse>rock</worse><market>sheet</market><thee>2015245207.0434046</thee><shells>behavior</shells></wet><unhappy>better</unhappy><snow>613209246</snow><continued>1248773262.53974</continued></family>";
			String PrivateKeyPath = "C:\\Users\\User\\Desktop\\pk\\";
			String PrivateKeyName = "cert.pfx";
			PasswordProtection keystorePassword = new PasswordProtection(("").toCharArray());
			String keystoreFile = PrivateKeyPath + PrivateKeyName;
			DSSDocument signDocument;
			
			signDocument = this.signDocument(InputXML, keystoreFile, keystorePassword);
			
			return ((InMemoryDocument)signDocument).getBytes();
		}catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	public DSSDocument signDocument(String pathToDocument, String keystore, PasswordProtection password) throws Exception {
		DSSDocument toSignDocument = new InMemoryDocument(pathToDocument.getBytes());	
		AbstractSignatureTokenConnection token;
		
		try (FileInputStream is = new FileInputStream(keystore)) {
			token = new Pkcs12SignatureToken(is, password);//JKSSignatureToken(is, password);
		} catch (Exception E) {
				throw new Exception(E.toString());
	    }

		//demo preserved from initial link
	    DSSPrivateKeyEntry privateKey = token.getKeys().get(0);

	    // Get the certificate corresponding to the key
	    CertificateToken signingCertificate = privateKey.getCertificate();

	    // Preparing parameters for the XAdES signature
	    XAdESSignatureParameters parameters = new XAdESSignatureParameters();
	    
	    //no need to comply to ETSI EN 319 132, will cause IssuerSerial substruct to follow V1 instead of V2
	    parameters.setEn319132(false);

	    //XAdES-T Enveloped signature w/ cannoncialization C14N11
	    parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);
	    parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
	    parameters.setSignedInfoCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE_11);
	    parameters.setSigningCertificate(signingCertificate);
	    
	    //set digest algo
	    parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
	    parameters.setSigningCertificateDigestMethod(DigestAlgorithm.SHA256);
	    
	    //transforms DSSReference
	    //code..
	    List<DSSTransform> dssTransformList = new ArrayList<>();
	    DSSNamespace ns = new DSSNamespace("http://www.w3.org/2000/09/xmldsig#", "ds");
	    DSSTransform transform, transform2;
	    if(false)
	    {
	    	transform = new customXPathTransform(ns, "http://www.w3.org/TR/1999/REC-xpath-19991116", "not(//ancestor-or-self::ext:UBLExtensions)");
	    	transform2 = new customXPathTransform(ns, "http://www.w3.org/TR/1999/REC-xpath-19991116", "not(//ancestor-or-self::cac:Signature)");
	    }else {
	    	transform = new XPathTransform(ns, "not(//ancestor-or-self::ext:UBLExtensions)");
	    	transform2 = new XPathTransform(ns, "not(//ancestor-or-self::cac:Signature)");
	    }
	    CanonicalizationTransform canonicalizationTransform = new CanonicalizationTransform(ns, CanonicalizationMethod.INCLUSIVE_11);
	    dssTransformList.add(transform);
	    dssTransformList.add(transform2);
	    dssTransformList.add(canonicalizationTransform);

	    List<DSSReference> references = new ArrayList<>();
	    DSSReference ref = new DSSReference();
	    ref.setContents(toSignDocument);
	    ref.setUri("");
	    ref.setId("id-doc-signed-data");
	    ref.setTransforms(dssTransformList);
	    ref.setDigestMethodAlgorithm(DigestAlgorithm.SHA256);
	    
	    references.add(ref);
	    
	    if(true)parameters.setReferences(references);
	    
	    //XPath for the transform specifies that the UBLExtensions and cac:Signature MUST not exist!
	    //signature to sit after ReferencedSignatureID
	    //parameters.setXPathLocationString("//sac:ReferenceSignatureID");
	    //parameters.setXPathElementPlacement(XPathElementPlacement.XPathFirstChildOf);
	    
	    CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
	    XAdESService service = new XAdESService(commonCertificateVerifier);
	    
	    //need to register other namespaces other than the ones delivered!
	    DomUtils.registerNamespace(new DSSNamespace("urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2","ext"));
	    DomUtils.registerNamespace(new DSSNamespace("urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2","cac"));
	    DomUtils.registerNamespace(new DSSNamespace("urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2","cbc"));
	    DomUtils.registerNamespace(new DSSNamespace("urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2","sig"));
		DomUtils.registerNamespace(new DSSNamespace("urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2","sac"));
		DomUtils.registerNamespace(new DSSNamespace("urn:oasis:names:specification:ubl:schema:xsd:SignatureBasicComponents-2","sbc"));
		
	    //set the timestamp source here. Procure an actual one for production!
	    OnlineTSPSource source = new OnlineTSPSource("https://freetsa.org/tsr");
	    service.setTspSource(source);
	    
	    // Get the SignedInfo XML segment that need to be signed.
	    ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);

	    // This function obtains the signature value for signed information using the private key and specified algorithm
	    SignatureValue signatureValue = token.sign(dataToSign, parameters.getDigestAlgorithm(), privateKey);
	    
	    // We invoke the service to sign the document with the signature value obtained in the previous step.
	    DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);
	    // THE DOCUMENT IS SIGNED AT THIS POINT		
	    
	    token.close();	//added to handle resource leak
	    return signedDocument;
	}
	
	public static void main(String args[]) throws Exception
	{
		Boolean activate = false;
		if(activate){
			String PrivateKeyPath = "C:\\Users\\User\\Desktop\\pk\\";
			String PrivateKeyName = "cert.pfx";
			PasswordProtection keystorePassword = new PasswordProtection(("").toCharArray());
			String keystoreFile = PrivateKeyPath + PrivateKeyName;		
			FileInputStream fs = new FileInputStream(keystoreFile);
			
			System.out.println("Starting FileInputStream :\t" + keystoreFile);
			
			try {
				int ctr= 0;
				while((ctr= fs.read()) != -1) {
					System.out.print((char) ctr);
				}
				System.out.println("\nIO Success");
			}catch (IOException e) {
				e.printStackTrace();
			}finally {
	            if (fs != null) {
	                try {
	                    fs.close();
	                } catch (IOException e) {
	                    e.printStackTrace();
	                }
	            }
			}
		} else {
			exampleXAdES_T_Imp test = new exampleXAdES_T_Imp();
			String retVal = new String(test.transform());
			System.out.println(retVal);
		}
	}
}

