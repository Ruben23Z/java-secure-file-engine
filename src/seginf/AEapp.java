package seginf;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.SecretKey;

//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
public class AEapp {
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeyException {
        //vai se chamar os metodos de cripto ou decripto
//le se o pdf como btes[]
//        File pdf = new File("documento.pdf");
//        byte[] mensagem = Files.readAllBytes(pdf.toPath()); // Java NIO

        File ficheiroRelatorio = new File("src/TP1_enunciado.pdf");
        byte[] BytesRelatorio = Files.readAllBytes(ficheiroRelatorio.toPath());

        SecretKey aesKey = CriptoUtil.makeAESChave();
        byte[] hmacKey = CriptoUtil.fazerHMAC(BytesRelatorio, aesKey);



    }
}