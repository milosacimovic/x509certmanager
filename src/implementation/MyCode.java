package implementation;

import java.io.*;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.Set;
import java.util.Vector;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierId;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.SubjectDirectoryAttributes;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;

import code.GuiException;
import gui.Constants;

public class MyCode extends x509.v3.CodeV3 {
	private KeyStore keystoreLoc; // String - alias, KeyPairCertInfo - all info
									// on keypairCert
	private String keystorePath;
	private String keystoreName;
	private String keystoreDir;
	private char[] keystorePass;
	private PKCS10CertificationRequest currentCSRequest;
	private static final String KEYSTORE_TYPE = "PKCS12";
	private static final String SIGN_ALGORITHM = "RSA";
	private static final int CA_BIT = 5;
	private static final String DOB_ID = "2.5.4.12";
	private static final String POB_ID = "2.5.4.7";
	private static final String COC_ID = "2.5.4.6";
	private static final String GENDER_ID = "2.5.4.43";
	private String currentKeypair;

	public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf) throws GuiException {
		super(algorithm_conf, extensions_conf);
		currentCSRequest = null;
	}
	static boolean isCritical(X509Certificate cer, String id){
		Set<String> set = cer.getCriticalExtensionOIDs();
		for(String str : set){
			if(str.equals(id)){
				return true;
			}
		}
		return false;
	}
	
	private void updateKeystore(){
		FileOutputStream keystoreOutS;
		try {
			keystoreOutS = new FileOutputStream(new File(keystorePath));
			keystoreLoc.store(keystoreOutS, keystorePass);
			keystoreOutS.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
		
	}

	@Override
	public boolean generateCSR(String keypair_name) {
		System.out.println("Generating CSR...");
		Key pubKey = null;
		Key privKey = null;
		X509Certificate cer = null;
		X500Principal namePrinc;
		X500Name name;
		PKCS10CertificationRequestBuilder builder;
		ContentSigner signer;
		PKCS10CertificationRequest csr;
		try {
			Key key = keystoreLoc.getKey(keypair_name, null);
			privKey = (PrivateKey) key;
			cer = (X509Certificate) keystoreLoc.getCertificate(keypair_name);
			pubKey = cer.getPublicKey();
			namePrinc = cer.getSubjectX500Principal();
			name = X500Name.getInstance(namePrinc.getEncoded());
			AsymmetricKeyParameter pubkeyParam = PublicKeyFactory.createKey(pubKey.getEncoded());
			SubjectPublicKeyInfo publicKeyInfo=SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(pubkeyParam);
			builder=new PKCS10CertificationRequestBuilder(name, publicKeyInfo);
			System.out.println("Sig alg name: " + cer.getSigAlgName());
			AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(cer.getSigAlgName()); 
	        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
			BcRSAContentSignerBuilder signerBuilder=new BcRSAContentSignerBuilder(sigAlgId, digAlgId);
			
			/* Certificate policies extension */
			byte[] cp = cer.getExtensionValue(Extension.certificatePolicies.toString());
			/* Subject Directory Attributes extension */
			byte[] sda = cer.getExtensionValue(Extension.subjectDirectoryAttributes.toString());
			/* Inhibit Any Policy extension */
			byte[] iap = cer.getExtensionValue(Extension.inhibitAnyPolicy.toString());
			ASN1OctetString octStr;
			ASN1Encodable[] encdbls;
			if (cp != null) {
				encdbls = new ASN1Encodable[2];
				if(isCritical(cer, Extension.certificatePolicies.toString())){
					encdbls[0] = new DERBMPString("true");
				}else{
					encdbls[0] = new DERBMPString("false");
				}
				octStr = ASN1OctetString.getInstance(cp);
				encdbls[1] = new DEROctetString(octStr.getOctets());
				builder.addAttribute(Extension.certificatePolicies, encdbls);
				
			}
			if (sda != null) {
				encdbls = new ASN1Encodable[2];
				if(isCritical(cer, Extension.subjectDirectoryAttributes.toString())){
					encdbls[0] = new DERBMPString("true");
				}else{
					encdbls[0] = new DERBMPString("false");
				}
				octStr = ASN1OctetString.getInstance(sda);
				encdbls[1] = new DEROctetString(octStr.getOctets());
				builder.addAttribute(Extension.subjectDirectoryAttributes, encdbls);
			}
			if (iap != null) {
				encdbls = new ASN1Encodable[2];
				if(isCritical(cer, Extension.inhibitAnyPolicy.toString())){
					encdbls[0] = new DERBMPString("true");
				}else{
					encdbls[0] = new DERBMPString("false");
				}
				octStr = ASN1OctetString.getInstance(iap);
				encdbls[1] = new DEROctetString(octStr.getOctets());
				builder.addAttribute(Extension.inhibitAnyPolicy, encdbls);
			}
			
			AsymmetricKeyParameter privKeyParam = PrivateKeyFactory.createKey(privKey.getEncoded());
			signer = signerBuilder.build(privKeyParam);
			csr = builder.build(signer);
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
		currentCSRequest = csr;

		return true;
	}

	@Override
	public String getIssuer(String keypair_name) {
		System.out.println("Getting Issuer...");
		X509Certificate cer;
		try {
			cer = (X509Certificate) keystoreLoc.getCertificate(keypair_name);
			X500Principal iss = cer.getIssuerX500Principal();
			return iss.getName();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public String getIssuerPublicKeyAlgorithm(String keypair_name) {
		System.out.println("Getting issuer public key algorithm...");
		X509Certificate cer;
		try {
			cer = (X509Certificate) keystoreLoc.getCertificate(keypair_name);
			PublicKey pubKey = cer.getPublicKey();
			return pubKey.getAlgorithm();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		return "";
	}

	// returns all CA's
	@Override
	public List<String> getIssuers(String keypair_name) {
		List<String> issuers = new ArrayList<>();
		System.out.println("Getting issuers suitable for signing " + keypair_name + "...");
		try {
			Enumeration<String> aliases = keystoreLoc.aliases();
			while (aliases.hasMoreElements()) {
				String str = aliases.nextElement();
				X509Certificate cert = (X509Certificate) keystoreLoc.getCertificate(str);
				if (cert.getBasicConstraints() != -1) {
					issuers.add(str);
				}
			}

		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		return issuers;
	}

	@Override
	public int getRSAKeyLength(String keypair_name) {
		System.out.println("Getting RSA key length...");
		X509Certificate cert;
		try {
			cert = (X509Certificate) keystoreLoc.getCertificate(keypair_name);
			RSAPublicKey key = (RSAPublicKey) cert.getPublicKey();
			// Need to fetch key length
			return key.getModulus().bitLength();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		return 0;
	}

	@Override // 0 - PEM , 1 - DER
	public boolean exportCertificate(File file, int encoding) {
		System.out.println("Exporting certificate...");
		X509Certificate cer;
		try {
			Certificate[] chain = keystoreLoc.getCertificateChain(currentKeypair);
			cer = (X509Certificate) chain[0];
			if (encoding == 1) {// PEM
				FileWriter fw = new FileWriter(file);
				JcaPEMWriter pw = new JcaPEMWriter(fw);
					PemObject po = new PemObject("CERTIFICATE", cer.getEncoded());
					pw.writeObject(po);
				pw.close();
			} else if (encoding == 1) {// DER
				FileOutputStream fos = new FileOutputStream(file);
				fos.write(cer.getEncoded());
				fos.close();
			}
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}

	@Override
	public boolean importCertificate(File file, String keypair_name) {
		System.out.println("Importing certificate..."); // if the file starts
														// with -----BEGIN
														// CERTIFICATE----- it
														// is a PEM file
														// otherwise DER

		try {
			if (keystoreLoc.containsAlias(keypair_name)) {
				return false;
			}
			FileInputStream fis = new FileInputStream(file);
			BufferedInputStream bis = new BufferedInputStream(fis);
			CertificateFactory certFact = CertificateFactory.getInstance("X.509");
			X509Certificate cer = (X509Certificate) certFact.generateCertificate(bis);
			keystoreLoc.setCertificateEntry(keypair_name, cer);
			updateKeystore();
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}

	@Override
	public boolean signCertificate(String issuer, String algorithm) {
		System.out.println("Signin certificate...");
		try {
			Certificate[] ch = keystoreLoc.getCertificateChain(issuer);
			X509Certificate issuerCert = (X509Certificate) keystoreLoc.getCertificate(issuer);
			int chainLen = ch.length + 1;
			int issuerChainLen = ch.length;
			// grab data from certificate request
			// grab the public key from the request
			// and verify the request
			// then take the name information from
			BcRSAContentVerifierProviderBuilder verifyBuilder = new BcRSAContentVerifierProviderBuilder(new DefaultDigestAlgorithmIdentifierFinder());
			AsymmetricKeyParameter pubKeyParam = PublicKeyFactory.createKey(currentCSRequest.getSubjectPublicKeyInfo());
			ContentVerifierProvider cvp = verifyBuilder.build(pubKeyParam);
			
			if (!currentCSRequest.isSignatureValid(cvp)) {
				return false;
			}
			CertificationRequest csr = currentCSRequest.toASN1Structure();
			CertificationRequestInfo csrInfo = csr.getCertificationRequestInfo();
			/* Subject name */
			X500Name subName = csrInfo.getSubject();
			/* Issuer name */
			X500Name issName = new X500Name(RFC4519Style.INSTANCE,issuerCert.getIssuerX500Principal().getName());
			/* Subject Public Key Info */
			SubjectPublicKeyInfo subPubInfo = csrInfo.getSubjectPublicKeyInfo();
			/* Both dates should be set by the CA */
			/* Date notBefore */
			Date notBefore = access.getNotBefore();
			/* Date notAfter */
			Date notAfter = access.getNotAfter();
			/* Serial */
			BigInteger serNum = new BigInteger(access.getSerialNumber());
			/* Extension */
			ASN1Encodable[] atrArr = csrInfo.getAttributes().toArray();
			X509v3CertificateBuilder certBuild = new X509v3CertificateBuilder(issName, serNum, notBefore, notAfter, subName, subPubInfo);
			for (int i = 0; i < atrArr.length; i++) {
				Attribute atr = Attribute.getInstance(atrArr[i]);
				ASN1Encodable[] encdbls = atr.getAttributeValues();
				boolean critical;
				DERBMPString str = DERBMPString.getInstance(encdbls[1]);
				if(str.getString().equals("true")){
					critical = true;
				}else{
					critical = false;
				}
				ASN1OctetString octStr = DEROctetString.getInstance(encdbls[0]);
				Extension ext;
				String id = atr.getAttrType().toString();
				if(id.equals(Extension.certificatePolicies.toString())){
					ext = new Extension(Extension.certificatePolicies, critical, octStr.getOctets());
					certBuild.addExtension(ext);
				}else if(id.equals(Extension.subjectDirectoryAttributes.toString())){
					ext = new Extension(Extension.subjectDirectoryAttributes, critical, octStr.getOctets());
					certBuild.addExtension(ext);
				}else if(id.equals(Extension.inhibitAnyPolicy.toString())){
					ASN1Integer derInt = ASN1Integer.getInstance(octStr.getOctets());
					System.out.println("derInt value : "+derInt.getValue());
					ext = new Extension(Extension.inhibitAnyPolicy, critical, derInt.getEncoded());
					certBuild.addExtension(ext);
				}
				
				
			}
			Certificate[] chain = new Certificate[chainLen];
			/*Signature*/
			PrivateKey privKey = (PrivateKey) keystoreLoc.getKey(issuer, null);
			AlgorithmIdentifier sigAlgId = currentCSRequest.getSignatureAlgorithm(); 
	        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
	        PrivateKeyInfo privKeyInfo = PrivateKeyInfo.getInstance(privKey.getEncoded());
	        ContentSigner cs = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(PrivateKeyFactory.createKey(privKeyInfo));
			X509CertificateHolder certHold = certBuild.build(cs);
	        chain[0] = new JcaX509CertificateConverter().getCertificate(certHold);
	        /*Creating cert chain of trust*/
			for (int i = 0; i < issuerChainLen; i++) {
				chain[i + 1] = ch[i];
			}
			Key pKey = keystoreLoc.getKey(currentKeypair, null);
			keystoreLoc.setKeyEntry(currentKeypair, pKey, null, chain);
			FileOutputStream fos = new FileOutputStream(new File(keystorePath));
			keystoreLoc.store(fos, keystorePass);
			fos.close();
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}

		return true;
	}

	@Override
	public Enumeration<String> loadLocalKeystore() {
		Enumeration<String> ret = null;
		keystoreName = "keystore.p12";
		keystorePass = "milosmld".toCharArray();
		keystoreDir = System.getProperty("user.dir");
		keystorePath = keystoreDir + File.separator + keystoreName;
		FileInputStream keystoreInS;
		try {
			keystoreLoc = KeyStore.getInstance(KEYSTORE_TYPE);
			File keystoreFile = new File(keystorePath);
			if (keystoreFile.exists()) {
				if (keystoreFile.length() != 0) {
					keystoreInS = new FileInputStream(keystoreFile);
					keystoreLoc.load(keystoreInS, keystorePass);
					keystoreInS.close();
				} else {
					keystoreLoc.load(null, keystorePass);
				}

			} else {
				keystoreLoc.load(null, keystorePass);
				updateKeystore();
			}
			ret = keystoreLoc.aliases();
		} catch (Exception e) {
			e.printStackTrace();
		}

		return ret;
	}

	@Override
	public void resetLocalKeystore() {
		try {
			Enumeration<String> aliases = keystoreLoc.aliases();
			List<String> aliasesStrs = new ArrayList<String>();
			while(aliases != null && aliases.hasMoreElements()){
				aliasesStrs.add(aliases.nextElement());
			}
			for(String str : aliasesStrs){
				keystoreLoc.deleteEntry(str);
			}
			updateKeystore();
		} catch (Exception e) {
			e.printStackTrace();
		}
		loadLocalKeystore();
	}

	@SuppressWarnings("rawtypes")
	@Override
	public int loadKeypair(String keypair_name) {
		X509Certificate c;
		int ret = -1;
		try {
			currentKeypair = keypair_name;
			c = (X509Certificate) keystoreLoc.getCertificate(keypair_name);
			if (c == null) {
				return ret;
			}

			/* Version */
			int ver = c.getVersion();
			access.setVersion(ver - 1);
			/* Subject name */
			X500Principal subName = c.getSubjectX500Principal();
			X500Principal issName = c.getIssuerX500Principal();
			access.setSubject(subName.getName());
			/* Validity period */
			Date notAfter = c.getNotAfter();
			Date notBefore = c.getNotBefore();
			access.setNotAfter(notAfter);
			access.setNotBefore(notBefore);

			/* SubjectPublicKeyInfo */
			String sigAlgName = c.getSigAlgName();
			access.setPublicKeyAlgorithm(sigAlgName);
			access.setSubjectSignatureAlgorithm(sigAlgName);
			access.setPublicKeySignatureAlgorithm(sigAlgName);
			RSAPublicKey key = (RSAPublicKey) c.getPublicKey();
			access.setPublicKeyParameter(Integer.valueOf(key.getModulus().bitLength()).toString());

			/* Serial Number */
			BigInteger serNum = c.getSerialNumber();
			access.setSerialNumber(serNum.toString());
			/* Extensions */
			/* critical */
			Set<String> setCrit = c.getCriticalExtensionOIDs();
			byte[] extValue;
			if (setCrit != null) {
				for (String oid : setCrit) {
					extValue = c.getExtensionValue(oid);
					ASN1OctetString octet = ASN1OctetString.getInstance(extValue);
					if (oid.equals(Extension.certificatePolicies.toString())) {
						access.setCritical(Constants.CP, true);
						CertificatePolicies certPol = CertificatePolicies.getInstance(octet.getOctets());
						PolicyInformation[] policies = certPol.getPolicyInformation();
						for (int i = 0; i < policies.length; i++) {
							ASN1Sequence seqCPS = policies[i].getPolicyQualifiers();
							PolicyQualifierInfo info = PolicyQualifierInfo.getInstance(seqCPS);
							if (info.getPolicyQualifierId().toString().equals(PolicyQualifierId.id_qt_cps.toString())) {
								access.setCpsUri(info.getQualifier().toString());
								access.setAnyPolicy(true);
							}
						}
					} else if (oid.equals(Extension.inhibitAnyPolicy.toString())) {
						octet = ASN1OctetString.getInstance(extValue);
						ASN1Integer skipcerts = ASN1Integer.getInstance(octet.getOctets());
						BigInteger scerts = skipcerts.getValue();
						access.setSkipCerts(scerts.toString());
						access.setInhibitAnyPolicy(true);
						access.setCritical(Constants.IAP, true);
					}
				}
			}
			/* non-critical */
			Set<String> setNonCrit = c.getNonCriticalExtensionOIDs();
			if (setNonCrit != null) {
				for (String oid : setNonCrit) {
					extValue = c.getExtensionValue(oid);
					ASN1OctetString octet = ASN1OctetString.getInstance(extValue);
					if (oid.equals(Extension.certificatePolicies.toString())) {
						CertificatePolicies certPol = CertificatePolicies.getInstance(octet.getOctets());
						PolicyInformation[] policies = certPol.getPolicyInformation();
						for (int i = 0; i < policies.length; i++) {
							ASN1Sequence seqCPS = policies[i].getPolicyQualifiers();
							PolicyQualifierInfo info = PolicyQualifierInfo.getInstance(seqCPS);
							if (info.getPolicyQualifierId().toString().equals(PolicyQualifierId.id_qt_cps.toString())) {
								access.setCpsUri(info.getQualifier().toString());
								access.setAnyPolicy(true);
							}
						}
						access.setCritical(Constants.CP, false);
					} else if (oid.equals(Extension.subjectDirectoryAttributes.toString())) {
						SubjectDirectoryAttributes atrs = SubjectDirectoryAttributes.getInstance(octet.getOctets());
						Vector v = atrs.getAttributes();
						for (int i = 0; i < v.size(); i++) {
							Attribute atr = Attribute.getInstance(v.elementAt(i));
							ASN1ObjectIdentifier attrid = atr.getAttrType();
							ASN1Encodable[] atrvalues = atr.getAttributeValues();
							ASN1Primitive val = atrvalues[0].toASN1Primitive();
							String strVal = val.toString();
							System.out.println("attr id : " + attrid.toString());
							System.out.println("value" + strVal);
							if (attrid.toString().equals(DOB_ID)) {// yyyyMMdd
								access.setDateOfBirth(strVal);
							} else if (attrid.toString().equals(POB_ID)) {
								access.setSubjectDirectoryAttribute(Constants.POB, strVal);
							} else if (attrid.toString().equals(COC_ID)) {
								access.setSubjectDirectoryAttribute(Constants.COC, strVal);
							} else if (attrid.toString().equals(GENDER_ID)) {
								access.setGender(strVal);
							}

						}
						access.setCritical(Constants.SDA, false);
					} else if (oid.equals(Extension.inhibitAnyPolicy.toString())) {
						octet = ASN1OctetString.getInstance(extValue);
						ASN1Integer skipcerts = ASN1Integer.getInstance(octet.getEncoded());
						BigInteger scerts = skipcerts.getValue();
						access.setSkipCerts(scerts.toString());
						access.setInhibitAnyPolicy(true);
						access.setCritical(Constants.IAP, false);
					}
				}
			}
			if (isCA(c)) {

				ret = 2;
				access.setCA(true);
			} else {
				access.setCA(false);
				if (subName.getName().equals(issName.getName())) {
					ret = 0;
				} else {
					ret = 1;
				}
			}
			if (ret == 1 || ret == 2) {
				access.setIssuer(issName.getName());
			}
			if (ret == 2) {
				access.setIssuerSignatureAlgorithm(sigAlgName);
			}
			if(ret == 1){
				/* Find issuer signature algorithm */
				Enumeration<String> aliases = keystoreLoc.aliases();
				while (aliases.hasMoreElements()) {
					String keypair = aliases.nextElement();
					if (!keypair.equals(keypair_name)) {
						X509Certificate cer = (X509Certificate) keystoreLoc.getCertificate(keypair);
						X500Principal cerSubName = cer.getSubjectX500Principal();
						if (cerSubName.getName().equals(issName.getName())) {
							access.setIssuerSignatureAlgorithm(cer.getSigAlgName());
						}
					}

				}
			}

		} catch (Exception e) {
			e.printStackTrace();
			return -1;
		}
		return ret;
	}

	// create a self-signed certificate
	@Override
	public boolean saveKeypair(String keypair_name) {
		System.out.println("Saving keypair...");
		KeyPairGenerator keyGen;
		try {
			keyGen = KeyPairGenerator.getInstance(SIGN_ALGORITHM);
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
		// construct certificate and private key
		/* PrivateKey */
		int keysize = Integer.parseInt(access.getPublicKeyParameter());
		keyGen.initialize(keysize);
		KeyPair keypair = keyGen.generateKeyPair();
		PrivateKey privKey = keypair.getPrivate();
		/* Certificate */
		/* Subject name */
		String subGUI = access.getSubject();
		System.out.println(subGUI);
		X500Name subName = new X500Name(RFC4519Style.INSTANCE, subGUI);
		/* Serial number */
		BigInteger serNum = new BigInteger(access.getSerialNumber());
		/* Date not Before */
		Date notBefore = access.getNotBefore();
		/* Date not After */
		Date notAfter = access.getNotAfter();
		/* Issuer name */
		X500Name issName = new X500Name(RFC4519Style.INSTANCE, subGUI);
		/* Subject Public Key Info */
		PublicKey subKeyInfo = keypair.getPublic();
		JcaX509v3CertificateBuilder certBuild = new JcaX509v3CertificateBuilder(issName, serNum, notBefore, notAfter,subName,
				subKeyInfo);
		/* Extensions */
		boolean critical = false;
		Extension ext;
		/* Certificate policies */
		if (access.getAnyPolicy()) {
			PolicyInformation[] pinfos = new PolicyInformation[1];
			if (access.isCritical(Constants.CP)) {
				critical = true;
			}
			ASN1ObjectIdentifier certPolId = ASN1ObjectIdentifier.getInstance(PolicyQualifierId.id_qt_cps);
			PolicyQualifierInfo[] policyQualifiers = new PolicyQualifierInfo[1];
			String cps = access.getCpsUri();
			DERBMPString str = new DERBMPString(cps);
			try{
				policyQualifiers[0] = new PolicyQualifierInfo(PolicyQualifierId.id_qt_cps, str.toASN1Primitive());

				pinfos[0] = new PolicyInformation(certPolId, ASN1Sequence.getInstance(policyQualifiers[0]));
				CertificatePolicies cp = new CertificatePolicies(pinfos);
				ext = new Extension(Extension.certificatePolicies, critical, cp.getEncoded());
				critical = false;
				certBuild.addExtension(ext);
				
			} catch (IOException e) {
				e.printStackTrace();
				return false;
			}

		}
		/* Subject Directory Attributes */
		String dob = access.getDateOfBirth();
	
		String pob = access.getSubjectDirectoryAttribute(Constants.POB);
		String coc = access.getSubjectDirectoryAttribute(Constants.COC);
		String gender = access.getGender();
		Vector<Attribute> v = new Vector<Attribute>();
		Attribute atr;
		if (!dob.equals("")) {
			
			ASN1Encodable[] encVec = new ASN1Encodable[]{(new DERBMPString(dob).toASN1Primitive())};
			DERSet set = new DERSet(encVec);
			ASN1Set s = ASN1Set.getInstance(set);
			atr = new Attribute(new ASN1ObjectIdentifier(DOB_ID), s);
			v.add(atr);
		}
		if (!pob.equals("")) {
			ASN1Encodable[] encVec = new ASN1Encodable[]{(new DERBMPString(pob).toASN1Primitive())};
			DERSet set = new DERSet(encVec);
			ASN1Set s = ASN1Set.getInstance(set);
			atr = new Attribute(new ASN1ObjectIdentifier(POB_ID), s);
			v.add(atr);
		}
		if (!coc.equals("")) {
			ASN1Encodable[] encVec = new ASN1Encodable[]{(new DERBMPString(coc).toASN1Primitive())};
			DERSet set = new DERSet(encVec);
			ASN1Set s = ASN1Set.getInstance(set);
			atr = new Attribute(new ASN1ObjectIdentifier(COC_ID), s);
			v.add(atr);
		}
		if(!gender.equals("")){
			ASN1Encodable[] encVec = new ASN1Encodable[]{(new DERBMPString(gender).toASN1Primitive())};
			DERSet set = new DERSet(encVec);
			ASN1Set s = ASN1Set.getInstance(set);
			atr = new Attribute(new ASN1ObjectIdentifier(GENDER_ID), s);
			v.add(atr);
		}
		
		if (!dob.equals("") || !pob.equals("") || !coc.equals("") || !gender.equals("")) {
			SubjectDirectoryAttributes attributes = new SubjectDirectoryAttributes(v);
			try {
				ext = new Extension(Extension.subjectDirectoryAttributes, false, attributes.getEncoded());
				certBuild.addExtension(ext);
			} catch (IOException e) {
				e.printStackTrace();
				return false;
			}
		}
		/* Inhibit any Policy */
		if (access.getInhibitAnyPolicy()) {
			if (access.isCritical(Constants.IAP)) {
				critical = true;
			}
			int skipcerts = Integer.parseInt(access.getSkipCerts());
			ASN1Integer derInt = new ASN1Integer(skipcerts);
			try {
				ext = new Extension(Extension.inhibitAnyPolicy, critical, derInt.getEncoded());
				certBuild.addExtension(ext);
			} catch (Exception e) {
				e.printStackTrace();
				return false;
			}
		}
		/* Self- sign generate certificate */		
		AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(access.getPublicKeySignatureAlgorithm()); 
        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
        PrivateKeyInfo privKeyInfo = PrivateKeyInfo.getInstance(privKey.getEncoded());
		ContentSigner cs;
		try {
			cs = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(PrivateKeyFactory.createKey(privKeyInfo));
			X509CertificateHolder certHold = certBuild.build(cs);
			X509Certificate cert = new JcaX509CertificateConverter().setProvider("SUN").getCertificate(certHold);
			Certificate[] chain = new Certificate[1];
			chain[0] = cert;
			keystoreLoc.setKeyEntry(keypair_name, privKey, null, chain);
			updateKeystore();
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}

	@Override
	public boolean importKeypair(String keypair_name, String file, String password) {
		File keypairFile = new File(file);
		FileInputStream fis = null;
		if (!keypairFile.exists() || keypairFile.length() == 0) {
			return false;
		}
		try {
			if (keystoreLoc.containsAlias(keypair_name)) {// alias taken
				return false;
			}
			KeyStore keystore = KeyStore.getInstance(KEYSTORE_TYPE);
			fis = new FileInputStream(keypairFile);
			keystore.load(fis, password.toCharArray());
			fis.close();
			Enumeration<String> e = keystore.aliases();
			while (e.hasMoreElements()) {
				String alias = e.nextElement();
				if (!keystore.isKeyEntry(alias)) {// not a key pair, but a
													// certificate
					return false;
				}
				Key key = keystore.getKey(alias, password.toCharArray());
				Certificate[] cc = keystore.getCertificateChain(alias);
				keystoreLoc.setKeyEntry(keypair_name, key, null, cc);
			}
			updateKeystore();
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}

		return true;
	}

	@Override
	public boolean exportKeypair(String keypair_name, String file, String password) {
		try {

			KeyStore key = KeyStore.getInstance(KEYSTORE_TYPE);
			key.load(null, password.toCharArray());
			Key entry = keystoreLoc.getKey(keypair_name, null);
			Certificate[] chain = keystoreLoc.getCertificateChain(keypair_name);
			File fileHandle = new File(file);
			if (fileHandle.isDirectory()) {
				fileHandle = new File(file + File.separator + keypair_name + ".p12");
			}
			if (!fileHandle.exists()) {
				fileHandle.createNewFile();

			}
			FileOutputStream fos = new FileOutputStream(fileHandle);
			key.setKeyEntry(keypair_name, entry, password.toCharArray(), chain);
			key.store(fos, password.toCharArray());
			fos.close();
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}

	@Override
	public boolean removeKeypair(String keypair_name) {

		try {
			keystoreLoc.deleteEntry(keypair_name);
			updateKeystore();
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}

		return true;
	}

	public boolean isCA(X509Certificate cert) {
		int basicConst = cert.getBasicConstraints();
		if (basicConst != -1) {
			return true;
		}
		boolean[] keyusage = cert.getKeyUsage();
		if (keyusage != null) {
			return keyusage[CA_BIT];
		}
		return false;
	}
}
