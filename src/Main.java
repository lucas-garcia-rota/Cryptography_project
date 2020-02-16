import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.*;

public class Main {
    private static KeyGenerator keyGen = null;
    private static File fileToEncrypt = new File("/Users/lucasgarciarota/IdeaProjects/Crypto_project/fichier_a_chiffre.txt");
    private static File encryptedFile = new File("/Users/lucasgarciarota/IdeaProjects/Crypto_project/encryptedFile");
    private static File decryptedFile = new File("/Users/lucasgarciarota/IdeaProjects/Crypto_project/decryptedFile");

    private static byte[] chiffrementAES(File fileToEncrypt, File fileEncrypted,SecretKey cle) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, IOException {

        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, cle);
        FileInputStream inputStream = new FileInputStream(fileToEncrypt);
        byte[] inputBytes = new byte[(int) fileToEncrypt.length()];
        inputStream.read(inputBytes);

        byte[] outputBytes = c.doFinal(inputBytes);

        FileOutputStream outputStream = new FileOutputStream(fileEncrypted);
        outputStream.write(outputBytes);
        inputStream.close();
        outputStream.close();
        return outputBytes;
    }

    private static byte[] dechiffrementAES(File encryptedFile, File decryptedFile, SecretKey cle) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException, InvalidAlgorithmParameterException {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, cle, new IvParameterSpec(new byte[16]));
        FileInputStream inputStream = new FileInputStream(encryptedFile);
        byte[] inputBytes = new byte[(int) encryptedFile.length()];
        inputStream.read(inputBytes);

        byte[] outputBytes = c.doFinal(inputBytes);

        FileOutputStream outputStream = new FileOutputStream(decryptedFile);
        outputStream.write(outputBytes);
        inputStream.close();
        outputStream.close();
        return  outputBytes;
    }

    public static void main(String[] argv) throws Exception {
        try {


            System.out.println("");
            System.out.println("Génération de la clé secrète AES et affichage...");
            System.out.println("");

            //Génération de la clé secrète AES et affichage de celle-ci

            keyGen = KeyGenerator.getInstance("AES");
            SecureRandom secureRandom = new SecureRandom();
            int keyBitSize = 256;
            keyGen.init(keyBitSize, secureRandom);
            SecretKey secretKey = keyGen.generateKey();
            System.out.println("Clé de type : " + secretKey.getAlgorithm() + ", format : " + secretKey.getFormat() +  " --> " + secretKey.getEncoded().toString());

            long  startTime = System.currentTimeMillis();

            //Chiffrement du fichier et affichage

            System.out.println("Chiffrement du fichier...");

            System.out.println("");

            byte [] enc = chiffrementAES(fileToEncrypt, encryptedFile,secretKey);
            for (int i = 0 ; i < enc.length ; ++i){
                System.out.print(String.format("%8s", Integer.toBinaryString(enc[i] & 0xFF)).replace(' ', '0') + " ");
            }

            System.out.println("");

            System.out.println("");
            System.out.println("");

            System.out.println("Déchiffrement du fichier...");
            System.out.println("");

            //Déchiffrement du fichier et affichage
            byte [] dec = dechiffrementAES(encryptedFile, decryptedFile, secretKey);
            for(int i = 0 ; i < dec.length ; ++i){
                System.out.print(String.format("%8s", Integer.toBinaryString(dec[i] & 0xFF)).replace(' ', '0') + " ");
            }
            System.out.println("");

            System.out.println("");
            System.out.println("");

            System.out.println("Temps d'exécution AES : " + (System.currentTimeMillis() - startTime) + " ms");
            System.out.println("");

        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

}
