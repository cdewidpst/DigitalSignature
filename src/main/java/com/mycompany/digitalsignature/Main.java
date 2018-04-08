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
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Image;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.CrlClient;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.ExternalSignature;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;
import com.itextpdf.text.pdf.security.OcspClient;
import com.itextpdf.text.pdf.security.PrivateKeySignature;
import com.itextpdf.text.pdf.security.TSAClient;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Collection;

public class Main {

    public static final String BASEDIR = "C:/Users/prashantagarwal/Desktop/digisign_data/";
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
        if (sign_img != null) {
            appearance.setLayer2Text("");
            appearance.setImage(Image.getInstance(sign_img));
            appearance.setImageScale(-1);
        }
        ExternalDigest digest = new BouncyCastleDigest();
        ExternalSignature signature = new PrivateKeySignature(pk, digestAlgorithm, provider);
        MakeSignature.signDetached(appearance, digest, signature, chain, crlList, ocspClient, tsaClient, estimatedSize, subfilter);
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
