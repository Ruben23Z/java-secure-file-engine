package seginf;

import javax.crypto.SecretKey;
import java.io.File;
import java.nio.file.Files;


public class AEapp {
    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            System.out.println("Uso: java AEapp [-cipher|-decipher] <ficheiro> <ficheiro_chave>");
            return;
        }

        String opcao = args[0]; // -cipher ou -decipher
        File inputFile = new File(args[1]);
        File inputKey = new File(args[2]);
        byte[] inputFileBytes = Files.readAllBytes(inputFile.toPath());

        SecretKey aesKey, MACKEY;
        File aesKeyFile = new File("aes.key");
        File hmacKeyFile = new File("certificates-keys/hmac.key");



        if (inputKey.exists()) {
            aesKey = CriptoUtil.LerChave(inputKey);
        } else {
            aesKey = CriptoUtil.makeAESChave();

            //escreve no ficheiro
            CriptoUtil.EscreverChave(inputKey, aesKey.getEncoded());
        }

        if(hmacKeyFile.exists())MACKEY = CriptoUtil.LerChave(hmacKeyFile);
        else {
            MACKEY = CriptoUtil.makeHMACChave();
            CriptoUtil.EscreverChave(hmacKeyFile, MACKEY.getEncoded());
        }


        if (opcao.equals("-cipher")) {
            String cifradoBase64 = AEEengine.Cifrar(inputFileBytes, aesKey, MACKEY);

            String nomeSemExt = inputFile.getName();
            int idx = nomeSemExt.lastIndexOf('.');
            if (idx > 0) nomeSemExt = nomeSemExt.substring(0, idx);

            Files.write(new File(nomeSemExt + ".aes").toPath(), cifradoBase64.getBytes());
            System.out.println("Ficheiro cifrado com sucesso!");


        } else if (opcao.equals("-decipher")) {
            String conteudoCifrado = Files.readString(inputFile.toPath());

            try {
                byte[] decifrado = AEEengine.Decifrar(conteudoCifrado, aesKey, MACKEY);
                String nomeSemExt = inputFile.getName();
                int idx = nomeSemExt.lastIndexOf('.');
                if (idx > 0) nomeSemExt = nomeSemExt.substring(0, idx);


                Files.write(new File("decifrado_TP1.pdf").toPath(), decifrado);
                System.out.println("Ficheiro decifrado e autenticado com sucesso!");
            } catch (SecurityException e) {
                System.out.println("Ficheiro corrompido ou HMAC inválido!");
            }
        } else {
            System.out.println("Opção inválida. Use -cipher ou -decipher.");

        }
    }
}