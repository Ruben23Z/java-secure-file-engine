package AssinaturaDigital;

import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.*;
import java.util.*;

public class RSASignVerify {
    public static void main(String[] args) throws Exception {

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
        System.out.println("Usando alias: " + chosenAlias);

//        PrivateKey PrivateKey = (PrivateKey) ks.getKey(alias, passChar); //devolve a chave privada associado
        // ao, aliás(usa se porque um keystore pode ter várias chaves), alice ou bob é o alises

        //o hash permite diminuir os bytes para a RSA operar mais eficientemente.
        Signature sig = ObterHashRSA(hash);
        sig.initSign(privateKey);

        LerFicheiroSig(file, sig);

        byte[] signBytes = sig.sign(); // devolve os byes binarios da assinatura
        String SignBase64 = Base64.getEncoder().encodeToString(signBytes);// codifica em DatabaseMetaData 64
//        System.out.println("Signature Base64: " + SignBase64);

//[arquivo grande]
//↓(lido em blocos de 8 KB)
//[Signature.update()] → alimenta o hash incrementalmente
//↓
//[hash final (SHA-256)]
//↓
//[encripta com chave privada RSA]
//↓
//[gera assinatura (256 bytes para RSA-2048)]

        //remove a extensão
        String nomeSemExt = file;
        int idx = nomeSemExt.lastIndexOf('.');
        if (idx > 0) nomeSemExt = nomeSemExt.substring(0, idx);

        Files.write(Path.of(nomeSemExt + ".sig"), signBytes);
        System.out.println("Sucesso");

    }

    public void Verify(String fileOriginal, String fileAssinatura,
                       String certFolha, String certIntermedio, String certRaiz, String hash) throws Exception {


        // Obtém o certificado a partir do ficheiro.cer
        X509Certificate leafCert = ObtemCertificado(certFolha);
        leafCert.checkValidity(); //verifica a data

        ArrayList<X509Certificate> certLista = new ArrayList<>();
        certLista.add(leafCert);
        certLista.add(ObtemCertificado(certIntermedio)); // CA intermédia

        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        CertPath certPath = factory.generateCertPath(certLista);

        Set<TrustAnchor> trustAnchors = new HashSet<>();
        trustAnchors.add(new TrustAnchor(ObtemCertificado(certRaiz), null));

        PKIXParameters params = new PKIXParameters(trustAnchors);
        params.setRevocationEnabled(false);

        CertPathValidator validator = CertPathValidator.getInstance("PKIX");
        try {
            validator.validate(certPath, params);
            System.out.println("Certificate chain validated (PKIX)");
        } catch (CertPathValidatorException | InvalidAlgorithmParameterException e) {
            // Se falhar aqui, o certificado não é confiável até as trust anchors fornecidas
            System.out.println("Certificate chain validation failed: " + e.getMessage());
            throw e;
        }

        PublicKey pk = leafCert.getPublicKey();//obtem se a chave publica
        Signature signature = ObterHashRSA(hash);
        signature.initVerify(pk);

        LerFicheiroSig(fileOriginal, signature);


        byte[] assinaturaBytes = Files.readAllBytes(Path.of(fileAssinatura));
        boolean verificacaoSucedida = signature.verify(assinaturaBytes);
        if (!verificacaoSucedida) System.out.println("Assinatura valica e certificado confiavel");
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


    public static void LerFicheiroSig(String file, Signature sig) throws Exception {
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

}