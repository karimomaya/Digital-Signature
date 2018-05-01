
package com.asset.signature;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

public abstract class CreateSignatureBase implements SignatureInterface
{
    private PrivateKey privateKey;
    protected Certificate certificate;
    private Certificate[] certificateChain;
    
    
    public CreateSignatureBase() {
        try {
            KeyStore keystore = KeyStore.getInstance("Windows-MY");
            keystore.load(null, null);
            
            
            PrivateKey oPrivateKey = null;
            for (Enumeration oEnum = keystore.aliases(); oEnum.hasMoreElements();) {                   
                String sAlias = (String) oEnum.nextElement();
                
                oPrivateKey = (PrivateKey) keystore.getKey(sAlias,null);
                Certificate[] certChain = keystore.getCertificateChain(sAlias);
                if (certChain == null){
                    continue;
                }
		 // if no keys continue ..
		if(oPrivateKey == null) continue;
                
                setPrivateKey(oPrivateKey);
                setCertificateChain(certChain);
                Certificate cert = keystore.getCertificate(sAlias);
                
                setCertificate(cert);
		System.out.println("Found a private key with Alias name:"+sAlias);
                break;
			 
            }
        } catch (KeyStoreException ex) {
            Logger.getLogger(CreateSignatureBase.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(CreateSignatureBase.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CreateSignatureBase.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {
            Logger.getLogger(CreateSignatureBase.class.getName()).log(Level.SEVERE, null, ex);
        } catch (UnrecoverableKeyException ex) {
            Logger.getLogger(CreateSignatureBase.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    public CreateSignatureBase(KeyStore keystore, char[] pin)  throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, IOException, CertificateException {
        Enumeration<String> aliases = keystore.aliases();
        String alias;
        Certificate cert = null;
        while (aliases.hasMoreElements()) {
            alias = aliases.nextElement();
            setPrivateKey((PrivateKey) keystore.getKey(alias, pin));
            Certificate[] certChain = keystore.getCertificateChain(alias);
            if (certChain == null) {
                continue;
            }
            setCertificateChain(certChain);
            cert = keystore.getCertificate(alias);
            setCertificate(cert);
            if (cert instanceof X509Certificate){
                // avoid expired certificate
                ((X509Certificate) cert).checkValidity();
            }
            break;
        }

        if (cert == null) {
            throw new IOException("Could not find certificate");
        }
    }

    public final void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public final void setCertificate(Certificate certificate) {
        this.certificate = certificate;
    }

    public final void setCertificateChain(final Certificate[] certificateChain) {
        
        this.certificateChain = certificateChain;
    }


    
    @Override
    public byte[] sign(InputStream content) throws IOException {
        try {
            List<Certificate> certList = new ArrayList<Certificate>();
            certList.addAll(Arrays.asList(certificateChain));
            certList.add(certificate);
            Store certs = new JcaCertStore(certList);
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            org.bouncycastle.asn1.x509.Certificate cert = org.bouncycastle.asn1.x509.Certificate.getInstance(ASN1Primitive.fromByteArray(certificate.getEncoded()));
            ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1WithRSA").build(privateKey);
            gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build()).build(sha1Signer, new X509CertificateHolder(cert)));
            gen.addCertificates(certs);
            CMSProcessableInputStream msg = new CMSProcessableInputStream(content);
            CMSSignedData signedData = gen.generate(msg, false);
            
            return signedData.getEncoded();
        } catch (GeneralSecurityException e) {
            throw new IOException(e);
        } catch (CMSException e) {
            throw new IOException(e);
        } catch (OperatorCreationException e) {
            throw new IOException(e);
        }
    }

    
    

    

    public int getMDPPermission(PDDocument doc) {
        COSBase base = doc.getDocumentCatalog().getCOSObject().getDictionaryObject(COSName.PERMS);
        if (base instanceof COSDictionary)
        {
            COSDictionary permsDict = (COSDictionary) base;
            base = permsDict.getDictionaryObject(COSName.DOCMDP);
            if (base instanceof COSDictionary)
            {
                COSDictionary signatureDict = (COSDictionary) base;
                base = signatureDict.getDictionaryObject("Reference");
                if (base instanceof COSArray)
                {
                    COSArray refArray = (COSArray) base;
                    for (int i = 0; i < refArray.size(); ++i)
                    {
                        base = refArray.getObject(i);
                        if (base instanceof COSDictionary)
                        {
                            COSDictionary sigRefDict = (COSDictionary) base;
                            if (COSName.DOCMDP.equals(sigRefDict.getDictionaryObject("TransformMethod")))
                            {
                                base = sigRefDict.getDictionaryObject("TransformParams");
                                if (base instanceof COSDictionary)
                                {
                                    COSDictionary transformDict = (COSDictionary) base;
                                    int accessPermissions = transformDict.getInt(COSName.P, 2);
                                    if (accessPermissions < 1 || accessPermissions > 3)
                                    {
                                        accessPermissions = 2;
                                    }
                                    return accessPermissions;
                                }
                            }
                        }
                    }
                }
            }
        }
        return 0;
    }

    public void setMDPPermission(PDDocument doc, PDSignature signature, int accessPermissions) {
        COSDictionary sigDict = signature.getCOSObject();

        COSDictionary transformParameters = new COSDictionary();
        transformParameters.setItem(COSName.TYPE, COSName.getPDFName("TransformParams"));
        transformParameters.setInt(COSName.P, accessPermissions);
        transformParameters.setName(COSName.V, "1.2");
        transformParameters.setNeedToBeUpdated(true);

        COSDictionary referenceDict = new COSDictionary();
        referenceDict.setItem(COSName.TYPE, COSName.getPDFName("SigRef"));
        referenceDict.setItem("TransformMethod", COSName.getPDFName("DocMDP"));
        referenceDict.setItem("DigestMethod", COSName.getPDFName("SHA1"));
        referenceDict.setItem("TransformParams", transformParameters);
        referenceDict.setNeedToBeUpdated(true);

        COSArray referenceArray = new COSArray();
        referenceArray.add(referenceDict);
        sigDict.setItem("Reference", referenceArray);
        referenceArray.setNeedToBeUpdated(true);

        COSDictionary catalogDict = doc.getDocumentCatalog().getCOSObject();
        COSDictionary permsDict = new COSDictionary();
        catalogDict.setItem(COSName.PERMS, permsDict);
        permsDict.setItem(COSName.DOCMDP, signature);
        catalogDict.setNeedToBeUpdated(true);
        permsDict.setNeedToBeUpdated(true);
    }
}
