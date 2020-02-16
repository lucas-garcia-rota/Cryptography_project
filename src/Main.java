import javax.crypto.*;
import java.security.*;

public class Main {
    private static KeyGenerator keyGen = null;
    private static KeyGenerator keyGenDES = null;
    private static KeyGenerator keyGen3DES = null;
    private static byte[] keyValue =
            new byte[]{(byte)'T', (byte)'h', (byte)'e', (byte)'B', (byte)'e', (byte)'s', (byte)'t', (byte)'S', (byte)'e', (byte)'c', (byte)'r', (byte)'e', (byte)'t', (byte)'K', (byte)'e', (byte)'y'};

    private static byte[] keyValueChanged =
            new byte[]{(byte)'T', (byte)'h', (byte)'i', (byte)'B', (byte)'e', (byte)'s', (byte)'t', (byte)'S', (byte)'e', (byte)'c', (byte)'r', (byte)'e', (byte)'t', (byte)'K', (byte)'e', (byte)'y'};

    private static byte[] chiffrementAES(byte[] message, SecretKey cle) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {

        Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, cle);
        return c.doFinal(message);
    }

    private static byte[] dechiffrementAES(byte[] message, SecretKey cle) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
        c.init(Cipher.DECRYPT_MODE, cle);
        return c.doFinal(message);
    }

    private static byte[] chiffrementDES(byte[] message, SecretKey cle) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {

        Cipher c = Cipher.getInstance("DES/ECB/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, cle);
        return c.doFinal(message);
    }

    private static byte[] dechiffrementDES(byte[] message, SecretKey cle) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher c = Cipher.getInstance("DES/ECB/NoPadding");
        c.init(Cipher.DECRYPT_MODE, cle);
        return c.doFinal(message);
    }

    private static byte[] chiffrement3DES(byte[] message, SecretKey cle) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {

        Cipher c = Cipher.getInstance("DESede/ECB/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, cle);
        return c.doFinal(message);
    }

    private static byte[] dechiffrement3DES(byte[] message, SecretKey cle) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher c = Cipher.getInstance("DESede/ECB/NoPadding");
        c.init(Cipher.DECRYPT_MODE, cle);
        return c.doFinal(message);
    }



    public static void main(String[] argv) throws Exception {
        try {

            System.out.println("Affichage de mes deux chaînes ...");
            System.out.println("");

            //Affichage en bits de mes chaînes de caractères

            for(int i = 0 ; i < keyValue.length ; ++i){
                System.out.print(String.format("%8s", Integer.toBinaryString(keyValue[i] & 0xFF)).replace(' ', '0') + " ");
            }

            System.out.println("");
            System.out.println("");

            for(int i = 0 ; i < keyValueChanged.length ; ++i){
                System.out.print(String.format("%8s", Integer.toBinaryString(keyValueChanged[i] & 0xFF)).replace(' ', '0') + " ");
            }
            System.out.println("");
            System.out.println("Génération de la clé secrète AES et affichage...");
            System.out.println("");

            //Génération de la clé secrète AES et affichage de celles ci

            keyGen = KeyGenerator.getInstance("AES");
            SecureRandom secureRandom = new SecureRandom();
            int keyBitSize = 256;
            keyGen.init(keyBitSize, secureRandom);
            SecretKey secretKey = keyGen.generateKey();
            System.out.println("Clé de type : " + secretKey.getAlgorithm() + ", format : " + secretKey.getFormat() +  " --> " + secretKey.getEncoded().toString());



            System.out.println("");
            System.out.println("");
            System.out.println("Génération de la clé secrète DES et affichage...");

            //Génération de la clé secrète DES et affichage de celle-ci

            keyGenDES = KeyGenerator.getInstance("DES");
            SecureRandom secureRandomDES = new SecureRandom();
            int keyBitSizeDES = 56;
            keyGenDES.init(keyBitSizeDES, secureRandomDES);
            SecretKey secretKeyDES = keyGenDES.generateKey();
            System.out.println("Clé de type : " + secretKeyDES.getAlgorithm() + ", format : " + secretKeyDES.getFormat() +  " --> " + secretKeyDES.getEncoded().toString());

            System.out.println("");
            System.out.println("");
            System.out.println("Génération de la clé secrète 3DES et affichage...");

            //Génération de la clé secrète DES et affichage de celle-ci

            keyGen3DES = KeyGenerator.getInstance("DESede");
            SecureRandom secureRandom3DES = new SecureRandom();
            int keyBitSize3DES = 112;
            keyGen3DES.init(keyBitSize3DES, secureRandom3DES);
            SecretKey secretKey3DES = keyGen3DES.generateKey();
            System.out.println("Clé de type : " + secretKey3DES.getAlgorithm() + ", format : " + secretKey3DES.getFormat() +  " --> " + secretKey3DES.getEncoded().toString());


            long  startTime = System.currentTimeMillis();

            System.out.println();

            System.out.println("__________METHODE AES__________");

            System.out.println("");

            //Chiffrement de ma chaîne et affichage de celles ci chiffrées

            System.out.println("Chiffrement de mes deux chaînes et affichage en chiffrées...");

            System.out.println("");

            byte [] enc = chiffrementAES(keyValue, secretKey);
            for (int i = 0 ; i < enc.length ; ++i){
                System.out.print(String.format("%8s", Integer.toBinaryString(enc[i] & 0xFF)).replace(' ', '0') + " ");
            }

            System.out.println("");

            byte [] enc1 = chiffrementAES(keyValueChanged, secretKey);
            for (int i = 0 ; i < enc1.length ; ++i){
                System.out.print(String.format("%8s", Integer.toBinaryString(enc1[i] & 0xFF)).replace(' ', '0') + " ");
            }

            System.out.println("");
            System.out.println("");

            System.out.println("Déchiffrement des deux chaînes et affichage déchiffrées...");
            System.out.println("");

            //Déchiffrement de ma chaîne et affichage de celle ci déchiffrée
            byte [] dec = dechiffrementAES(enc, secretKey);
            for(int i = 0 ; i < dec.length ; ++i){
                System.out.print(String.format("%8s", Integer.toBinaryString(dec[i] & 0xFF)).replace(' ', '0') + " ");
            }
            System.out.println("");

            byte [] dec1 = dechiffrementAES(enc1, secretKey);
            for(int i = 0 ; i < dec1.length ; ++i){
                System.out.print(String.format("%8s", Integer.toBinaryString(dec1[i] & 0xFF)).replace(' ', '0') + " ");
            }
            System.out.println("");
            System.out.println("");

            System.out.println("Temps d'exécution AES : " + (System.currentTimeMillis() - startTime));
            System.out.println("");

            long startTimeDES = System.currentTimeMillis();

            System.out.println("__________METHODE DES__________");

            System.out.println("");

            //Chiffrement de mes deux châines et affichage de celles-ci chifrées

            System.out.println();
            System.out.println("Chiffrement de mes deux chaînes et affichage en chiffrées...");
            System.out.println("");

            byte [] encDES = chiffrementDES(keyValue, secretKeyDES);
            for (int i = 0 ; i < encDES.length ; ++i){
                System.out.print(String.format("%8s", Integer.toBinaryString(encDES[i] & 0xFF)).replace(' ', '0') + " ");
            }

            System.out.println("");

            byte [] enc1DES = chiffrementDES(keyValueChanged, secretKeyDES);
            for (int i = 0 ; i < enc1.length ; ++i){
                System.out.print(String.format("%8s", Integer.toBinaryString(enc1DES[i] & 0xFF)).replace(' ', '0') + " ");
            }

            System.out.println("");
            System.out.println("");

            System.out.println("Déchiffrement des deux chaînes et affichage déchiffrées...");
            System.out.println("");

            //Déchiffrement de ma chaîne et affichage de celle ci déchiffrée
            byte [] decDES = dechiffrementDES(encDES, secretKeyDES);
            for(int i = 0 ; i < decDES.length ; ++i){
                System.out.print(String.format("%8s", Integer.toBinaryString(decDES[i] & 0xFF)).replace(' ', '0') + " ");
            }
            System.out.println("");

            byte [] dec1DES = dechiffrementDES(enc1DES, secretKeyDES);
            for(int i = 0 ; i < dec1.length ; ++i){
                System.out.print(String.format("%8s", Integer.toBinaryString(dec1DES[i] & 0xFF)).replace(' ', '0') + " ");
            }
            System.out.println("");
            System.out.println("");

            System.out.println("Temps d'exécution DES : " + (System.currentTimeMillis() - startTimeDES));

            long  startTime3DES = System.currentTimeMillis();

            System.out.println();

            System.out.println("__________METHODE 3DES__________");

            System.out.println("");

            //Chiffrement de ma chaîne et affichage de celles ci chiffrées

            System.out.println("Chiffrement de mes deux chaînes et affichage en chiffrées...");

            System.out.println("");

            byte [] enc3DES = chiffrement3DES(keyValue, secretKey3DES);
            for (int i = 0 ; i < enc3DES.length ; ++i){
                System.out.print(String.format("%8s", Integer.toBinaryString(enc3DES[i] & 0xFF)).replace(' ', '0') + " ");
            }

            System.out.println("");

            byte [] enc13DES = chiffrement3DES(keyValueChanged, secretKey3DES);
            for (int i = 0 ; i < enc1.length ; ++i){
                System.out.print(String.format("%8s", Integer.toBinaryString(enc13DES[i] & 0xFF)).replace(' ', '0') + " ");
            }

            System.out.println("");
            System.out.println("");

            System.out.println("Déchiffrement des deux chaînes et affichage déchiffrées...");
            System.out.println("");

            //Déchiffrement de ma chaîne et affichage de celle ci déchiffrée
            byte [] dec3DES = dechiffrement3DES(enc3DES, secretKey3DES);
            for(int i = 0 ; i < dec3DES.length ; ++i){
                System.out.print(String.format("%8s", Integer.toBinaryString(dec3DES[i] & 0xFF)).replace(' ', '0') + " ");
            }
            System.out.println("");

            byte [] dec13DES = dechiffrement3DES(enc13DES, secretKey3DES);
            for(int i = 0 ; i < dec13DES.length ; ++i){
                System.out.print(String.format("%8s", Integer.toBinaryString(dec13DES[i] & 0xFF)).replace(' ', '0') + " ");
            }
            System.out.println("");
            System.out.println("");

            System.out.println("Temps d'exécution 3DES : " + (System.currentTimeMillis() - startTime3DES));
            System.out.println("");

        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

}
