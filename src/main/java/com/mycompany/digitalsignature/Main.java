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
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Date;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;


public class Main {

    public static String BASEDIR = "C:/Users/prashantagarwal/Desktop/digisign_data/";
    public static String CERT_FILE_NAME = "certificate";
    public static String CERT_FILE_EXT = "pfx";
    public static String SIGN_IMG_FILE_NAME = "sign";
    public static String SIGN_IMG_FILE_EXT = "jpg";
    public static String SUPP_FILES_DIR_NAME = "supporting_files/";
    public static String UNSIGNED_DOCS_DIR_NAME = "unsigned_docs/";
    public static String SIGNED_DOCS_DIR_NAME = "signed_docs/";
    public static String LOG_FILE_NAME = "log.csv";
    public static String LOG_FILE_DELIMITER = ",";
    public static String TMP_LOG_FILE_NAME = BASEDIR + "logTmp.csv";
    public static String DIGEST_ALGO = "SHA512";
    public static String SIGN_REASON = "Test Sign";
    public static String SIGN_LOCATION = "BPCL";
    public static String SIGN_FIELD_NAME = "sign_bpcl";
    public static int ESTIMATED_SIZE_SIGNED = 1500;
    public static int SIGN_POSITION_X_COOR = 380;
    public static int SIGN_POSITION_Y_COOR = 68;
    public static int SIGN_BOX_LENGTH = 90;
    public static int SIGN_BOX_HEIGHT = 42;
    
    public static final String CONFIG_PATH = "C:/Users/prashantagarwal/Desktop/digisign_data/config.json";
    
    public static String status, remarks, msg_code;
    public static PrivateKey pk;
    public static Certificate[] chain;
    public static Date date;
    public static void main(String[] args) throws Exception {
        date = new Date();
        int sno = 0;
        readConfig(CONFIG_PATH);
        String pfx_file_path, pfx_file_pass, sign_img, src_pdf, dest_pdf;
        BufferedWriter writerTmp, writer;
        String user_dir, supporting_dir, unsigned_docs_dir, signed_docs_dir;
        File user_dir_file, supporting_dir_file, unsigned_docs_dir_file, signed_docs_dir_file;
        try {
            writerTmp = new BufferedWriter(new FileWriter(TMP_LOG_FILE_NAME));
            writeLog(writerTmp, "Sno", "BillDocNo", "Status", "MessageCode", "Remarks");
            writeLog(writerTmp, "1", "", "S", "S01", "writer object creation successful.");
        } catch (Exception ex) {
            return;
        }
        if (args.length == 0) {
            writeLog(writerTmp, "2", "", "E", "E02", "args[0] i.e. sy-uname not specified.");
            writerTmp.close();
            return;
        } else {
            if (args[0] == null) {
                writeLog(writerTmp, "2", "", "E", "E02", "args[0] i.e. sy-uname not specified.");
                writerTmp.close();
                return;
            } else {
                try {
                    writer = new BufferedWriter(new FileWriter(BASEDIR + args[0] + "/" + LOG_FILE_NAME));
                    writeLog(writer, "Sno", "BillDocNo", "Status", "MessageCode", "Remarks");
                    sno++;
                    writeLog(writer, sno + "", "Start DateTime", "", "", date.toString());
                    sno++;
                    writeLog(writer, sno + "", "", "S", "S10", "writer object creation successful.");
                    sno++;
                    writeLog(writer, sno + "", "", "S", "S11", "args[0] i.e. sy-uname present successful.");
                } catch (Exception exe) {
                    writeLog(writerTmp, "3", "", "E", "E03", exe.getMessage());
                    writerTmp.close();
                    return;
                }
            }
        }
        if (args.length < 2) {
            sno++;
            writeLog(writer, sno + "", "", "E", "E12", "args[1] i.e. password not specified.");
            closeWriter(writer, writerTmp);
            return;
        } else {
            if (args[1] == null) {
                sno++;
                writeLog(writer, sno + "", "", "E", "E12", "args[1] i.e. password not specified.");
                closeWriter(writer, writerTmp);
                return;
            } else {
                pfx_file_pass = args[1];
                sno++;
                writeLog(writer, sno + "", "", "S", "S12", "args[1] i.e. password present successful.");
            }
        }
        try {
            user_dir = BASEDIR + args[0] + "/";
            user_dir_file = new File(user_dir);
            sno++;
            writeLog(writer, sno + "", "", "S", "S13", "User dir file object creation successful.");
        } catch (Exception e1) {
            sno++;
            writeLog(writer, sno + "", "", "E", "E13", e1.getMessage());
            closeWriter(writer, writerTmp);
            return;
        }
        if (!user_dir_file.exists()) {
            sno++;
            writeLog(writer, sno + "", "", "E", "E14", "User directory does not exist.");
            closeWriter(writer, writerTmp);
            return;
        } else {
            sno++;
            writeLog(writer, sno + "", "", "S", "S14", "User directory exist successful.");
        }
        if (!user_dir_file.isDirectory()) {
            sno++;
            writeLog(writer, sno + "", "", "E", "E15", "User directory specified is not folder.");
            closeWriter(writer, writerTmp);
            return;
        } else {
            sno++;
            writeLog(writer, sno + "", "", "S", "S15", "User directory folder check successful.");
        }
        try {
            supporting_dir = user_dir + SUPP_FILES_DIR_NAME;
            supporting_dir_file = new File(supporting_dir);
            sno++;
            writeLog(writer, sno + "", "", "S", "S16", "Supporting files dir file object creation successful.");
        } catch (Exception e2) {
            sno++;
            writeLog(writer, sno + "", "", "E", "E16", e2.getMessage());
            closeWriter(writer, writerTmp);
            return;
        }
        if (!supporting_dir_file.exists()) {
            sno++;
            writeLog(writer, sno + "", "", "E", "E17", "Supporting Files directory does not exist.");
            closeWriter(writer, writerTmp);
            return;
        } else {
            sno++;
            writeLog(writer, sno + "", "", "S", "S17", "Supporting Files directory exist successful.");
        }
        if (!supporting_dir_file.isDirectory()) {
            sno++;
            writeLog(writer, sno + "", "", "E", "E18", "Supporting Files directory specified is not folder.");
            closeWriter(writer, writerTmp);
            return;
        } else {
            sno++;
            writeLog(writer, sno + "", "", "S", "S18", "Supporting Files directory folder check successful.");
        }
        pfx_file_path = supporting_dir + CERT_FILE_NAME + "." + CERT_FILE_EXT;
        if (!new File(pfx_file_path).exists()) {
            sno++;
            writeLog(writer, sno + "", "", "E", "E19", "Certificate file does not exist.");
            closeWriter(writer, writerTmp);
            return;
        } else {
            sno++;
            writeLog(writer, sno + "", "", "S", "S19", "Certificate file exist successful.");
        }
        sign_img = supporting_dir + SIGN_IMG_FILE_NAME + "." + SIGN_IMG_FILE_EXT;
        if (!new File(sign_img).exists()) {
            sign_img = null;
        }
        try {
            unsigned_docs_dir = user_dir + UNSIGNED_DOCS_DIR_NAME;
            unsigned_docs_dir_file = new File(unsigned_docs_dir);
            sno++;
            writeLog(writer, sno + "", "", "S", "S20", "Unsigned docs dir file object creation successful.");
        } catch (Exception e3) {
            sno++;
            writeLog(writer, sno + "", "", "E", "E20", e3.getMessage());
            closeWriter(writer, writerTmp);
            return;
        }
        if (!unsigned_docs_dir_file.exists()) {
            sno++;
            writeLog(writer, sno + "", "", "E", "E21", "Unsigned Docs directory does not exist.");
            closeWriter(writer, writerTmp);
            return;
        } else {
            sno++;
            writeLog(writer, sno + "", "", "S", "S21", "Unsigned Docs directory exist successful.");
        }
        if (!supporting_dir_file.isDirectory()) {
            sno++;
            writeLog(writer, sno + "", "", "E", "E22", "Unsigned Docs directory specified is not folder.");
            closeWriter(writer, writerTmp);
            return;
        } else {
            sno++;
            writeLog(writer, sno + "", "", "S", "S22", "Unsigned docs directory folder check successful.");
        }
        try {
            signed_docs_dir = user_dir + SIGNED_DOCS_DIR_NAME;
            signed_docs_dir_file = new File(signed_docs_dir);
            sno++;
            writeLog(writer, sno + "", "", "S", "S23", "Signed docs dir file object creation successful.");
        } catch (Exception e4) {
            sno++;
            writeLog(writer, sno + "", "", "E", "E23", e4.getMessage());
            closeWriter(writer, writerTmp);
            return;
        }
        char signed_docs_dir_flag = 'A';
        if (signed_docs_dir_file.exists()) {
            if (signed_docs_dir_file.isFile()) {
                signed_docs_dir_file.delete();
                signed_docs_dir_flag = 'X';
                sno++;
                writeLog(writer, sno + "", "", "S", "S24-A", "Signed Docs dir does not exists but file exists.");
            } else {
                sno++;
                writeLog(writer, sno + "", "", "S", "S24-B", "Signed Docs dir exists.");
                try {
                    File[] file_tmp = signed_docs_dir_file.listFiles();
                    for (File file : file_tmp) {
                        file.delete();
                    }
                    sno++;
                    writeLog(writer, sno + "", "", "S", "S25-A", "Making Signed Docs dir empty successful.");
                } catch (Exception e5) {
                    sno++;
                    writeLog(writer, sno + "", "", "E", "E25-A", e5.getMessage());
                    closeWriter(writer, writerTmp);
                    return;
                }
            }
        } else {
            signed_docs_dir_flag = 'X';
            sno++;
            writeLog(writer, sno + "", "", "S", "S24-C", "Signed Docs dir does not exists.");
        }
        if (signed_docs_dir_flag == 'X') {
            try {
                signed_docs_dir_file.mkdirs();
                sno++;
                writeLog(writer, sno + "", "", "S", "S25-B", "Signed docs dir file folder creation successful.");
            } catch (Exception e6) {
                sno++;
                writeLog(writer, sno + "", "", "E", "E25-B", e6.getMessage());
                closeWriter(writer, writerTmp);
                return;
            }
        }
        File[] unsigned_docs_files = unsigned_docs_dir_file.listFiles();
        if (unsigned_docs_files.length == 0) {
            sno++;
            writeLog(writer, sno + "", "", "E", "E26", "No unsigned docs present.");
            closeWriter(writer, writerTmp);
            return;
        } else {
            sno++;
            writeLog(writer, sno + "", "", "S", "S26", "Unsigned docs dir not empty successful.");
        }
        if (getCertificateAndPk(pfx_file_path, pfx_file_pass)) {
            sno++;
            writeLog(writer, sno + "", "", "S", "S27", "Read certificate and password verified successful.");
        } else {
            sno++;
            writeLog(writer, sno + "", "", status, msg_code, remarks);
            closeWriter(writer, writerTmp);
            return;
        }
        for (File file : unsigned_docs_files) {
            sno++;
            if (file.isFile() && (file.getName().endsWith(".pdf") || file.getName().endsWith(".PDF"))) {
                src_pdf = unsigned_docs_dir + file.getName();
                dest_pdf = signed_docs_dir + file.getName();
                status = null;
                msg_code = null;
                remarks = null;
                sign(src_pdf, dest_pdf, sign_img,
                        chain, pk, DIGEST_ALGO, null, CryptoStandard.CMS,
                        SIGN_REASON, SIGN_LOCATION,
                        null, null, null, ESTIMATED_SIZE_SIGNED);
                writeLog(writer, sno + "", file.getName().toUpperCase().replaceAll(".PDF", ""), status, msg_code, remarks);
//                file.delete();
            } else {
                writeLog(writer, sno + "", file.getName(), "E", "E28-A", "File is not PDF.");
            }
        }
        closeWriter(writer, writerTmp);
    }
    
    public static void readConfig(String config_path){
        try{
            JSONParser parser = new JSONParser();
            JSONObject obj = (JSONObject)parser.parse(new FileReader(config_path));
            if((String)(String)obj.get("base_dir") != null){
                BASEDIR = (String)obj.get("base_dir");
            }
            if((String)obj.get("cert_file_name") != null){
                CERT_FILE_NAME = (String)obj.get("cert_file_name");
            }
            if((String)obj.get("cert_file_ext") != null){
                CERT_FILE_EXT = (String)obj.get("cert_file_ext");
            }
            if((String)obj.get("sign_img_file_name") != null){
                SIGN_IMG_FILE_NAME = (String)obj.get("sign_img_file_name");
            }
            if((String)obj.get("sign_img_file_ext") != null){
                SIGN_IMG_FILE_EXT = (String)obj.get("sign_img_file_ext");
            }
            if((String)obj.get("supp_files_dir_name") != null){
                SUPP_FILES_DIR_NAME = (String)obj.get("supp_files_dir_name");
            }
            if((String)obj.get("unsigned_docs_dir_name") != null){
                UNSIGNED_DOCS_DIR_NAME = (String)obj.get("unsigned_docs_dir_name");
            }
            if((String)obj.get("signed_docs_dir_name") != null){
                SIGNED_DOCS_DIR_NAME = (String)obj.get("signed_docs_dir_name");
            }
            if((String)obj.get("log_file_name") != null){
                LOG_FILE_NAME = (String)obj.get("log_file_name");
            }
            if((String)obj.get("log_file_delimiter") != null){
                LOG_FILE_DELIMITER = (String)obj.get("log_file_delimiter");
            }
            if((String)obj.get("tmp_log_file_name") != null){
                TMP_LOG_FILE_NAME = BASEDIR +  (String)obj.get("tmp_log_file_name");
            }
            if((String)obj.get("digest_algo") != null){
                DIGEST_ALGO = (String)obj.get("digest_algo");
            }
            if((String)obj.get("sign_reason") != null){
                SIGN_REASON = (String)obj.get("sign_reason");
            }
            if((String)obj.get("sign_location") != null){
                SIGN_LOCATION = (String)obj.get("sign_location");
            }
            if((String)obj.get("sign_field_name") != null){
                SIGN_FIELD_NAME = (String)obj.get("sign_field_name");
            }
            if(Integer.parseInt((String)obj.get("estimated_size_signed")) != -1){
                ESTIMATED_SIZE_SIGNED = Integer.parseInt((String)obj.get("estimated_size_signed"));
            }
            if(Integer.parseInt((String)obj.get("sign_position_x_coor")) != -1){
                SIGN_POSITION_X_COOR = Integer.parseInt((String)obj.get("sign_position_x_coor"));
            }
            if(Integer.parseInt((String)obj.get("sign_position_y_coor")) != -1){
                SIGN_POSITION_Y_COOR = Integer.parseInt((String)obj.get("sign_position_y_coor"));
            }
            if(Integer.parseInt((String)obj.get("sign_box_length")) != -1){
                SIGN_BOX_LENGTH = Integer.parseInt((String)obj.get("sign_box_length"));
            }
            if(Integer.parseInt((String)obj.get("sign_box_height")) != -1){
                SIGN_BOX_HEIGHT = Integer.parseInt((String)obj.get("sign_box_height"));
            }
        }catch(Exception ex){
            System.out.println(ex.getMessage());
        }
    }
    
    public static boolean getCertificateAndPk(String pfx_file_path, String pfx_file_pass) {
        try {
            KeyStore ks = KeyStore.getInstance("pkcs12");
            ks.load(new FileInputStream(pfx_file_path), pfx_file_pass.toCharArray());
            String alias = (String) ks.aliases().nextElement();
            pk = (PrivateKey) ks.getKey(alias, pfx_file_pass.toCharArray());
            chain = ks.getCertificateChain(alias);
        } catch (IOException e1) {
            status = "E";
            msg_code = "E27-A";
            remarks = e1.getMessage();
            return false;
        } catch (Exception e) {
            status = "E";
            msg_code = "E27-B";
            remarks = e.getMessage();
            return false;
        }
        return true;
    }

    public static void sign(String src, String dest, String sign_img,
            Certificate[] chain,
            PrivateKey pk, String digestAlgorithm, String provider,
            CryptoStandard subfilter,
            String reason, String location,
            Collection<CrlClient> crlList,
            OcspClient ocspClient,
            TSAClient tsaClient,
            int estimatedSize) {
        try {
            // Creating the reader and the stamper
            PdfReader reader = new PdfReader(src);
            FileOutputStream os = new FileOutputStream(dest);
            PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0');
            // Creating the appearance
            PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
            appearance.setReason(reason);
            appearance.setLocation(location);
            appearance.setVisibleSignature(new Rectangle(SIGN_POSITION_X_COOR, SIGN_POSITION_Y_COOR,
                                                            SIGN_POSITION_X_COOR + SIGN_BOX_LENGTH, 
                                                            SIGN_POSITION_Y_COOR + SIGN_BOX_HEIGHT),
                                            1, SIGN_FIELD_NAME);
            if (sign_img != null) {
                appearance.setLayer2Text("");
                appearance.setImage(Image.getInstance(sign_img));
                appearance.setImageScale(-1);
            }
            ExternalDigest digest = new BouncyCastleDigest();
            ExternalSignature signature = new PrivateKeySignature(pk, digestAlgorithm, provider);
            MakeSignature.signDetached(appearance, digest, signature, chain, crlList, ocspClient, tsaClient, estimatedSize, subfilter);
            status = "S";
            msg_code = "S28";
            remarks = "Successfully signed";
        } catch (IOException e1) {
            status = "E";
            msg_code = "E28-B";
            remarks = e1.getMessage();
            return;
        } catch (DocumentException e2) {
            status = "E";
            msg_code = "E28-C";
            remarks = e2.getMessage();
            return;
        } catch (Exception e) {
            status = "E";
            msg_code = "E28-D";
            remarks = e.getMessage();
            return;
        }
    }

    public static void writeLog(BufferedWriter writer,
            String sno,
            String item,
            String status,
            String msgCode,
            String remarks) {
        if (writer != null) {
            try {
                if (item == "") {
                    item = "NA";
                }
                String writerString = sno + LOG_FILE_DELIMITER
                        + item + LOG_FILE_DELIMITER
                        + status + LOG_FILE_DELIMITER
                        + msgCode + LOG_FILE_DELIMITER
                        + remarks + LOG_FILE_DELIMITER + "\n";
                writer.write(writerString);
            } catch (Exception ex) {
                System.out.println(ex.getMessage());
            }
        }
    }

    public static void closeWriter(BufferedWriter writer, BufferedWriter writerTmp) {
        try {
            date = new Date();
            writeLog(writer, "", "End DateTime", "", "", date.toString());
            writer.close();
            writerTmp.close();
            new File(TMP_LOG_FILE_NAME).delete();
        } catch (Exception ex) {
            writeLog(writerTmp, "3", "", "E", "E04", "Error writing log file." + ex.getMessage());
            try {
                writerTmp.close();
            } catch (Exception ex1) {
                System.out.println(ex1.getMessage());
            }
        }
    }
}
