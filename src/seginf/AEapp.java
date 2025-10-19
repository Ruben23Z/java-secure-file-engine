package seginf;

import javax.crypto.SecretKey;
import java.io.File;
import java.nio.file.Files;


public class AEapp {
    public static void main(String[] args) throws Exception {
//compilar
//javac seginf/*.java

//cifra do PDF
//java seginf.AEapp -cipher TP1_enunciado.pdf aes.key

//Decifra do PDF
//java seginf.AEapp -decipher TP1_enunciado.aes aes.key


        if (args.length != 3) {
            System.out.println("Uso: java AEapp [-cipher|-decipher] <ficheiro> <ficheiro_chave>");
            return;
        }
        //obtem os valores dados do cmd
        String opcao = args[0]; // -cipher ou -decipher
        File inputFile = new File(args[1]); // escreve depois a chave se esta não existir neste file
        File inputKey = new File(args[2]);
        byte[] inputFileBytes = Files.readAllBytes(inputFile.toPath()); // transforma em bytes do ficheiro do pdf

        SecretKey aesKey, MACKEY; // cria as cahves que vai usar

        File hmacKeyFile = new File("hmac.key");


        if (inputKey.exists()) aesKey = CriptoUtil.LerChave(inputKey); // verifica se a chave existe, se sim le
        else {
            aesKey = CriptoUtil.makeAESChave(); // senão cria a chave AES aleatoria de 128

            //escreve no ficheiro
            CriptoUtil.EscreverChave(inputKey, aesKey.getEncoded()); // escreve a chave no ficheiro dado no terminal
        }

        if (hmacKeyFile.exists()) MACKEY = CriptoUtil.LerChave(hmacKeyFile); //verifica se a chave existe, se sim le
        else {
            MACKEY = CriptoUtil.makeHMACChave(); // cria a chave HMAC de 128 aleatoria
            CriptoUtil.EscreverChave(hmacKeyFile, MACKEY.getEncoded()); // cria a chave no file criado para o HMAC
        }


        if (opcao.equals("-cipher")) {
            String cifradoBase64 = AEEengine.Cifrar(inputFileBytes, aesKey, MACKEY); // cifra passando o ficheiro dado, a chave AES e MACKEY

            String nomeSemExt = inputFile.getName();
            int idx = nomeSemExt.lastIndexOf('.');
            if (idx > 0) nomeSemExt = nomeSemExt.substring(0, idx);

            Files.write(new File(nomeSemExt + ".aes").toPath(), cifradoBase64.getBytes());
            System.out.println("Ficheiro cifrado com sucesso!");


        } else if (opcao.equals("-decipher")) {
            String conteudoCifrado = Files.readString(inputFile.toPath());

            try {
                byte[] decifrado = AEEengine.Decifrar(conteudoCifrado, aesKey, MACKEY);
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