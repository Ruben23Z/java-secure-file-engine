package AssinaturaDigital;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.*;
import java.util.*;

public class RSASignVerify {
    public static void main(String[] args) throws Exception {

//Compilar
//javac AssinaturaDigital/RSASignVerify.java

//# Assinar o ficheiro (Alice)
//java AssinaturaDigital.RSASignVerify sign TP1_enunciado.pdf certificates-keys/pfx/Alice_1.pfx changeit sha256

//# Verificar com a cadeia da CA1 (válida)
//java AssinaturaDigital.RSASignVerify verify TP1_enunciado.pdf TP1_enunciado_Alice_1.sig certificates-keys/end-entities/Alice_1.cer certificates-keys/intermediates/CA1-int.cer certificates-keys/trust-anchors/CA1.cer sha256
//java AssinaturaDigital.RSASignVerify verify TP1_enunciado.pdf TP1_enunciado_Bob_2.sig certificates-keys/end-entities/Alice_1.cer certificates-keys/intermediates/CA1-int.cer certificates-keys/trust-anchors/CA1.cer sha256

//# Verificar com a cadeia da CA2 (inválida)
//java AssinaturaDigital.RSASignVerify verify TP1_enunciado.pdf TP1_enunciado_Alice1.sig certificates-keys/end-entities/Bob_2.cer certificates-keys/intermediates/CA2-int.cer certificates-keys/trust-anchors/CA2.cer sha256
//java AssinaturaDigital.RSASignVerify verify TP1_enunciado.pdf TP1_enunciado_Bob_2.sig certificates-keys/end-entities/Bob_2.cer certificates-keys/intermediates/CA2-int.cer certificates-keys/trust-anchors/CA2.cer sha256

        if (args.length < 1) {
            System.out.println("Uso: java RSASignVerify <acao> <parametros>");
            System.out.println("Acoes:");
            System.out.println("  sign <arquivo> <keystore.p12> <senha> <hash>");
            System.out.println("  verify <arquivo> <assinatura> <certFolha> <certIntermedio> <certRaiz> <hash>");
            return;
        }


        //obtem os valores dados do cmd
        String opcao = args[0]; // -cipher ou -decipher

        if (opcao.equalsIgnoreCase("sign")) {
            if (args.length != 5) {
                System.out.println("Uso: sign <arquivo> <keystore.p12> <senha> <hash>");
                return;
            }
            String arquivo = args[1];
            String keystore = args[2];
            String senha = args[3];
            String hash = args[4];

            Sign(arquivo, keystore, senha, hash);

        } else if (opcao.equalsIgnoreCase("verify")) {
            if (args.length != 7) {
                System.out.println("Uso: verify <arquivo> <assinatura> <certFolha> <certIntermedio> <certRaiz> <hash>");
                return;
            }
            String arquivo = args[1];
            String assinatura = args[2];
            String certFolha = args[3];
            String certIntermedio = args[4];
            String certRaiz = args[5];
            String hash = args[6];

            Verify(arquivo, assinatura, certFolha, certIntermedio, certRaiz, hash);

        } else {
            System.out.println("Ação inválida: " + opcao);
        }
    }


    public static void Sign(String file, String keyStore, String password, String hash) throws Exception {

        char[] passChar = password.toCharArray(); //pode ser limpo da memória dps do uso

        KeyStore ks = KeyStore.getInstance("PKCS12"); //o keystore PKCS12 é que le a extensão pkx
        //carrega os certificados e chaves contidas neste
        ks.load(new FileInputStream(keyStore), passChar); //le o ficheiro da keystore e desencripta com a password

        Enumeration<String> aliases = ks.aliases();
        PrivateKey privateKey = null;
        String chosenAlias = null;
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (ks.isKeyEntry(alias)) {
                Key key = ks.getKey(alias, passChar);
                if (key instanceof PrivateKey) {
                    privateKey = (PrivateKey) key;
                    chosenAlias = alias;
                    break;
                }
            }
        }
        if (privateKey == null) throw new Exception("Nenhuma chave privada encontrada no KeyStore");

        System.out.println("Usando alias: " + chosenAlias);
        Arrays.fill(passChar, '\0');
//        PrivateKey PrivateKey = (PrivateKey) ks.getKey(alias, passChar); //devolve a chave privada associado
        // ao, aliás(usa se porque um keystore pode ter várias chaves), alice ou bob é o alises

        //o hash permite diminuir os bytes para a RSA operar mais eficientemente.
        Signature sig = ObterHashRSA(hash);
        sig.initSign(privateKey);

        SigIncremental(file, sig);

        byte[] signBytes = sig.sign(); // devolve os byes binarios da assinatura
        String SignBase64 = Base64.getEncoder().encodeToString(signBytes);// codifica em DatabaseMetaData 64
//        System.out.println("Signature Base64: " + SignBase64);


        //remove a extensão
        String nomeSemExt = nomeSemExtensao(file);
        String nomePFX = new File(keyStore).getName();
        nomePFX = nomeSemExtensao(nomePFX);
        String assinturaFile= nomeSemExt +"_"+ nomePFX+".sig";

        Files.write(Path.of(assinturaFile), signBytes);
        System.out.println("Assinatura gerada com sucesso: " + assinturaFile + ".sig");
    }

    public static void Verify(String fileOriginal, String fileAssinatura,
                              String certFolha, String certIntermedio, String certRaiz, String hash) throws Exception {


        // Obtém o certificado a partir do ficheiro.cer
        X509Certificate leafCert = ObtemCertificado(certFolha);
        leafCert.checkValidity(); //verifica a data

        ArrayList<X509Certificate> certLista = new ArrayList<>();
        certLista.add(leafCert);
        certLista.add(ObtemCertificado(certIntermedio)); // CA intermédia

        //cria a cadeia desde o certificado folha até aos intermédios
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        CertPath certPath = factory.generateCertPath(certLista);

        Set<TrustAnchor> trustAnchors = new HashSet<>();
        trustAnchors.add(new TrustAnchor(ObtemCertificado(certRaiz), null));

        PKIXParameters params = new PKIXParameters(trustAnchors);
        params.setRevocationEnabled(false);

        CertPathValidator validator = CertPathValidator.getInstance("PKIX");
        try {
            validator.validate(certPath, params);
            System.out.println("Certificado de cadeia validado (PKIX)");
        } catch (CertPathValidatorException | InvalidAlgorithmParameterException e) {
            // Se falhar aqui, o certificado não é confiável até as trust anchors fornecidas
            System.out.println("Certificado de cadeia falhou: " + e.getMessage());
        }

        PublicKey pk = leafCert.getPublicKey();//obtem se a chave publica
        Signature signature = ObterHashRSA(hash);
        signature.initVerify(pk);

        SigIncremental(fileOriginal, signature);


        byte[] assinaturaBytes = Files.readAllBytes(Path.of(fileAssinatura));//desncripta a assinatura recebida com a PubK
        boolean verificacaoSucedida = signature.verify(assinaturaBytes);//compara com a calculada

        if (verificacaoSucedida) System.out.println("Assinatura valica e certificado confiavel");
        else System.out.println("Assinatura invalida");

    }


    public static Signature ObterHashRSA(String hash) throws Exception {
        if (hash.equalsIgnoreCase("sha1")) {
            return Signature.getInstance("SHA1withRSA");
        } else if (hash.equalsIgnoreCase("sha256")) {
            return Signature.getInstance("SHA256withRSA");
        } else {
            throw new IllegalArgumentException("Hash dado Invalido");
        }
    }

    //[arquivo grande]
//↓(lido em blocos de 8 KB)
//[Signature.update()] → alimenta o hash incrementalmente
//↓
//[hash final (SHA-256)]
//↓
//[encripta com chave privada RSA]
//↓
//[gera assinatura (256 bytes para RSA-2048)]
    public static void SigIncremental(String file, Signature sig) throws Exception {
        try (FileInputStream fis = new FileInputStream(file)) { //abre o fileinput para ler o ficheiro
            byte[] buffer = new byte[8192]; //8kb
            int read;
            while ((read = fis.read(buffer)) != -1) { //le ate 8Kb
                sig.update(buffer, 0, read);//envia para o sig os bytes lidos
            }
        }
    }

    public static X509Certificate ObtemCertificado(String nomeFicheiro) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        try (FileInputStream fis = new FileInputStream(nomeFicheiro)) {
            return (X509Certificate) factory.generateCertificate(fis);
        }
    }

    public static String nomeSemExtensao(String file) {
        if (file == null) return null;

        int idx = file.lastIndexOf('.');
        if (idx > 0) {
            return file.substring(0, idx);
        }
        return file;
    }

}