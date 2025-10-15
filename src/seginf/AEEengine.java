package seginf;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.util.Arrays;
import java.util.Base64;

public class AEEengine {

//AE(k)(m)=E(k)(m)∣∣T(k)(E(k)(m))

//E(k)(m) → cifrar a mensagem m com AES-CBC + PKCS5 padding
//T(k)(E(k)(m)) → calcular HMAC-SHA256 da mensagem cifrada
//Concatenar os dois e gravar/retornar (em Base64, se desejado)

    public static String Cifrar(byte[] mensagem, SecretKey aesKey, SecretKey hmacKey) throws Exception {
        IvParameterSpec iv = CriptoUtil.generateIV();

        // Gera o objeto da cifra simetrica
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        // Associa a chave key a cifra
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
        byte[] cifratext = cipher.doFinal(mensagem);
        //E(k)(m)

        // usa o (E(k)(m)) egera a tal =>T(k)(E(k)(m))
        byte[] HmacFicheiro = CriptoUtil.fazerHMAC(cifratext, hmacKey);

        byte[] resultado = new byte[iv.getIV().length + cifratext.length + HmacFicheiro.length];

        //rraycopy(Object source_arr, int sourcePos,Object dest_arr, int destPos, int len)
        System.arraycopy(iv.getIV(), 0, resultado, 0, iv.getIV().length);
        System.arraycopy(cifratext, 0, resultado, iv.getIV().length, cifratext.length);
        System.arraycopy(HmacFicheiro, 0, resultado, iv.getIV().length + cifratext.length, HmacFicheiro.length);

        // converte para Base64 para salvar
        return CriptoUtil.Base64Encode(resultado);//[IV (16 bytes)] [Ciphertext (variável)] [HMAC (32 bytes)]
    }


    //    boolean decrypt(File inputBase64, File keyFile, File outputPlain) — devolve autenticidade
    public static byte[] Decifrar(String inputBase64, SecretKey aeskey, SecretKey hmackey) throws Exception {

        byte[] resultado = Base64.getDecoder().decode(inputBase64);

        byte[] ivBytes = Arrays.copyOfRange(resultado, 0, 16);
        byte[] cifraBytes = Arrays.copyOfRange(resultado, 16, resultado.length - 32);
        byte[] hmacRecebido = Arrays.copyOfRange(resultado, resultado.length - 32, resultado.length);

        boolean autentico = CriptoUtil.verificarHMAC(cifraBytes, hmacRecebido, hmackey);
        if (!autentico)
            throw new SecurityException("HMAC recebida e HMAC calculado é diferentes, a mensagem foi alterado");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aeskey, new IvParameterSpec(ivBytes));
        //        System.out.println("Decifrado: " + Base64.getEncoder().encodeToString(decifra));
        return cipher.doFinal(cifraBytes);
    }
}
