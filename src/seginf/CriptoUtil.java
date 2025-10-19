package seginf;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;


public class CriptoUtil {


    //le os bytes da chave finaria do ficheiro e verifica o tamanho
    public static SecretKey LerChave(File keyFile) throws IOException {
        try (FileInputStream fis = new FileInputStream(keyFile)) {
            byte[] keyBytes = fis.readAllBytes();
            int len = keyBytes.length;

            if (len != 16 && len != 24 && len != 32) {
                throw new IllegalArgumentException(
                        "Tamanho da chave AES invalida: " + len + " bytes (tem que ser 16, 24, or 32)"
                );
            }
            return new SecretKeySpec(keyBytes, "AES");
        }
    }

    //quando se quer gerar e guardar uma nova chave simetrica
    public static void EscreverChave(File keyFile, byte[] keyBytes) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(keyFile)) {
            fos.write(keyBytes);
        }
    }


    public static IvParameterSpec generateIV() {
        int AES_BLOCK_SIZE = 16; // bytes

        SecureRandom sr = new SecureRandom();
        byte[] iv = new byte[AES_BLOCK_SIZE];
        sr.nextBytes(iv); // prenche o array com os bytes aleatorios
        // AES block size = 16 bytes
        return new IvParameterSpec(iv);
    }


    public static SecretKey makeAESChave() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        SecureRandom secRandom = new SecureRandom();
        keyGen.init(128, secRandom);
        SecretKey key = keyGen.generateKey();
        return key;
    }

    // Gera uma chave para o HMAC (autenticação)
    public static SecretKey makeHMACChave() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
        SecureRandom secRandom = new SecureRandom();
        keyGen.init(256, secRandom);
        return keyGen.generateKey();
    }

    //faz o Hmac da data
    public static byte[] fazerHMAC(byte[] data, SecretKey key) throws Exception {
        // Obtém objeto MAC e inicia com a chave
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        // Computa o HMAC da mensagem
        return mac.doFinal(data);
    }

    public static boolean verificarHMAC(byte[] dataRecebido, byte[] MacParaVerificar, SecretKey keyRecebido) throws Exception {

        byte[] novoMac = fazerHMAC(dataRecebido, keyRecebido);
        return Arrays.equals(novoMac, MacParaVerificar); // compara conteúdo
    }

    public static String Base64Encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    public static byte[] Base64Decode(String data) {
        return (Base64.getDecoder().decode(data));
    }


}

