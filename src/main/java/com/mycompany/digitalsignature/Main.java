/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.mycompany.digitalsignature;

/**
 *
 * @author prashantagarwal
 */
import com.itextpdf.text.BaseColor;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Image;
import com.itextpdf.text.Paragraph;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.ColumnText;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.PdfTemplate;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.CertificateUtil;
import com.itextpdf.text.pdf.security.CrlClient;
import com.itextpdf.text.pdf.security.CrlClientOnline;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.ExternalSignature;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;
import com.itextpdf.text.pdf.security.OcspClient;
import com.itextpdf.text.pdf.security.OcspClientBouncyCastle;
import com.itextpdf.text.pdf.security.PrivateKeySignature;
import com.itextpdf.text.pdf.security.TSAClient;
import com.itextpdf.text.pdf.security.TSAClientBouncyCastle;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
//import static org.bouncycastle.asn1.x500.style.RFC4519Style.name;
//import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Main {

    public static final String BASEDIR = "C:/Users/prashantagarwal/Desktop/digisign_data/";
    public static final String KEYSTORE = "C:/Users/prashantagarwal/Desktop/digisign_data/ks";
    public static final char[] PASSWORD = "password".toCharArray();
    public static final String SRC = "C:/Users/prashantagarwal/Desktop/digisign_data/invoice_cpy.pdf";
    public static final String DEST = "C:/Users/prashantagarwal/Desktop/digisign_data/hello_signed%s.pdf";
    public static final String IMG = "C:/Users/prashantagarwal/Desktop/digisign_data/sign_small_size.jpg";
    public static String pfx_file_path, pfx_file_pass, sign_img, src_pdf, dest_pdf;

    public static void main(String[] args) throws Exception {
        String dir1, dir2, dir3, dir4;
        if (args[0] != null && args[1] != null) {
            dir1 = BASEDIR + args[0] + "/";
            File f1 = new File(dir1);
            if (f1.exists() && f1.isDirectory()) {
                dir2 = dir1 + "supporting_files/";
                File f2 = new File(dir2);
                if (f2.exists() && f2.isDirectory()) {
                    pfx_file_path = dir2 + "certificate.pfx";
                    sign_img = dir2 + "sign.jpg";
                    if (!new File(sign_img).exists()) {
                        sign_img = null;
                    }
                    pfx_file_pass = args[1];
                    dir4 = dir1 + "unsigned_docs/";
                    File[] list_files = new File(dir4).listFiles();
                    dir3 = dir1 + "signed_docs/";
                    if(!new File(dir3).exists()){
                        new File(dir3).mkdir();
                    }
                    BufferedWriter writer = new BufferedWriter(new FileWriter(dir1 + "log.csv"));
                    writer.write("SNo,BillDocNo,Status,Remarks\n");
                    int sno = 0;
                    for (File file : list_files) {
                        sno++;
                        if (file.isFile() && (file.getName().endsWith(".pdf") || file.getName().endsWith(".PDF"))) {
                            src_pdf = dir4 + file.getName();
                            System.out.println(src_pdf);
                            dest_pdf = dir3 + file.getName();
                            System.out.println(dest_pdf);
                            signWithoutBouncy(src_pdf, dest_pdf);
                            writer.write(sno+","+file.getName().toUpperCase().replaceAll(".PDF","")+",S,successfully signed\n");
//                            file.delete();
                        }
                        else{
                            writer.write(sno+","+file.getName()+",E,File is not PDF\n");
                        }
                    }
                    writer.close();
                }
            }
        }
//        signCert();
//        signWithoutBouncy();
//        BouncyCastleProvider provider = new BouncyCastleProvider();
//        Security.addProvider(provider);
//        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
//        ks.load(new FileInputStream(KEYSTORE), PASSWORD);
//        String alias = (String) ks.aliases().nextElement();
//        PrivateKey pk = (PrivateKey) ks.getKey(alias, PASSWORD);
//        Certificate[] chain = ks.getCertificateChain(alias);
//        sign(SRC, String.format(DEST, 1), chain, pk, "MD5", provider.getName(), CryptoStandard.CMS, "Test Sign", "BPCL",null,null,null,0);
//        sign(SRC, String.format(DEST, 2), chain, pk, DigestAlgorithms.SHA512, provider.getName(), CryptoStandard.CMS, "Test Sign", "BPCL",null,null,null,0);
//        sign(SRC, String.format(DEST, 3), chain, pk, DigestAlgorithms.SHA256, provider.getName(), CryptoStandard.CADES, "Test Sign", "BPCL",null,null,null,0);
//        sign(SRC, String.format(DEST, 4), chain, pk, DigestAlgorithms.RIPEMD160, provider.getName(), CryptoStandard.CADES, "Test Sign", "BPCL",null,null,null,0);
    }

    public static void sign(String src, String dest,
            Certificate[] chain,
            PrivateKey pk, String digestAlgorithm, String provider,
            CryptoStandard subfilter,
            String reason, String location,
            Collection<CrlClient> crlList,
            OcspClient ocspClient,
            TSAClient tsaClient,
            int estimatedSize)
            throws GeneralSecurityException, IOException, DocumentException {
        // Creating the reader and the stamper
        PdfReader reader = new PdfReader(src);
        FileOutputStream os = new FileOutputStream(dest);
        PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0');
        // Creating the appearance
        PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
        appearance.setReason(reason);
        appearance.setLocation(location);
        appearance.setVisibleSignature(new Rectangle(380, 68, 470, 110), 1, "sig");
// Creating the appearance for layer 0
//        PdfTemplate n0 = appearance.getLayer(0);
//        float x = n0.getBoundingBox().getLeft();
//        float y = n0.getBoundingBox().getBottom();
//        float width = n0.getBoundingBox().getWidth();
//        float height = n0.getBoundingBox().getHeight();
//        n0.setColorFill(BaseColor.LIGHT_GRAY);
//        n0.rectangle(x, y, width, height);
//        n0.fill();
// Creating the appearance for layer 2
//        PdfTemplate n2 = appearance.getLayer(2);
//        ColumnText ct = new ColumnText(n2);
//        ct.setSimpleColumn(n2.getBoundingBox());
        if (sign_img != null) {
            appearance.setLayer2Text("");
            appearance.setImage(Image.getInstance(IMG));
            appearance.setImageScale(-1);
        }
//        ct.addElement(p);
//        ct.go();
// Creating the signature
        ExternalDigest digest = new BouncyCastleDigest();
        ExternalSignature signature = new PrivateKeySignature(pk, digestAlgorithm, provider);
        MakeSignature.signDetached(appearance, digest, signature, chain, crlList, ocspClient, tsaClient, estimatedSize, subfilter);
    }

    public static void signCert() throws Exception {
//        BouncyCastleProvider provider = new BouncyCastleProvider();
//        Security.addProvider(provider);
//        KeyStore ks = KeyStore.getInstance("pkcs12", provider.getName());
//        ks.load(new FileInputStream("resources/alice.pfx"), "testpassword".toCharArray());
//        ks.load(new FileInputStream("resources/certificate.pfx"), "passw0rd".toCharArray());
//        String alias = (String)ks.aliases().nextElement();
//        System.err.println(alias);
//        PrivateKey pk = (PrivateKey) ks.getKey(alias, "".toCharArray());
//        Certificate[] chain = ks.getCertificateChain(alias);
//        for(int i=0 ; i< chain.length;i++) {
//            X509Certificate cert = (X509Certificate)chain[i];
//            System.out.println(String.format("[%s] %s", i, cert.getSubjectDN()));
//            System.out.println(CertificateUtil.getCRLURL(cert));
//            System.out.println(CertificateUtil.getOCSPURL(cert));
//            System.out.println(CertificateUtil.getTSAURL(cert));
//        }
//        List<CrlClient> crlList = new ArrayList<CrlClient>();
//        crlList.add(new CrlClientOnline());
//        crlList.add(new CrlClientOnline(chain));

//        OcspClient ocspClient = new OcspClientBouncyCastle();
//        TSAClient tsaClient = new TSAClientBouncyCastle(tsaUrl, tsaUser, tsaPass);
//        sign(SRC, "resources/pfx_signed_alice.pdf", chain, pk, "MD5", provider.getName(), CryptoStandard.CMS, "Test Sign", "BPCL",crlList,null,null,0);
    }

    public static void signWithoutBouncy(String src_pdf, String dest_pdf) throws Exception {
        KeyStore ks = KeyStore.getInstance("pkcs12");
//        ks.load(new FileInputStream("C:/Users/prashantagarwal/Desktop/digisign_data/alice.pfx"), "testpassword".toCharArray());
//        ks.load(new FileInputStream("C:/Users/prashantagarwal/Desktop/digisign_data/certificate.pfx"), "passw0rd".toCharArray());
        ks.load(new FileInputStream(pfx_file_path), pfx_file_pass.toCharArray());
        String alias = (String) ks.aliases().nextElement();
        System.err.println(alias);
        PrivateKey pk = (PrivateKey) ks.getKey(alias, pfx_file_pass.toCharArray());
//        PrivateKey pk = (PrivateKey) ks.getKey(alias, "passw0rd".toCharArray());
        Certificate[] chain = ks.getCertificateChain(alias);
        sign(src_pdf, dest_pdf, chain, pk, "MD5", null, CryptoStandard.CMS, "Test Sign", "BPCL", null, null, null, 1500);
    }
}
