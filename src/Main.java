import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

/**
 * Created by Sheldon on 18/02/2016.
 *
 * {@link #encrypt(String, String)} and
 * {@link #decrypt(String, String)}
 * methods modified from implementation at
 * @see <a href="http://rosettacode.org/wiki/Vigen%C3%A8re_cipher#Java">rosettacode</a>
 */
public class Main {

    final static private int MAX_KEY_LENGTH = 5;   //Set max key length for deciphering

    public static void main(String[] args) {
        Scanner scan = new Scanner(System.in);
        int choice = 0;

        //Present choices
        while(choice < 1 || choice > 3) {
            System.out.println("Vignere Program:\n1: Encrypt\n2: Decrypt\n3: Decipher\n\nEnter choice:");
            choice = scan.nextInt();
            scan.nextLine();    //Ignore newline
            if(choice < 1 || choice > 3) {
                System.out.println("INVALID CHOICE\n\n");
            }
        }

        switch(choice) {
            case 1:
                System.out.println("Enter message to be encrypted:");
                String plaintext = scan.nextLine();

                System.out.println("Enter key:");
                String eKey = scan.nextLine().toUpperCase();

                System.out.println(encrypt(plaintext, eKey));
                break;
            case 2:
                System.out.println("Enter message to be decrypted:");
                String ciphertext = scan.nextLine();

                System.out.println("Enter key:");
                String dKey = scan.nextLine().toUpperCase();

                System.out.println(decrypt(ciphertext, dKey));
                break;
            case 3:
                System.out.println("Enter message to be decrypted:");
                String text = scan.nextLine();

                decipher(text);
                break;
        }

    }


    /**
     * Encrypts the plaintext using the supplied key
     * @param plaintext Text to be encrypted
     * @param key       Key to be used for encryption
     * @return  The encrypted ciphertext
     */
    static String encrypt(String plaintext, final String key) {
        String result = "";
        plaintext = plaintext.toUpperCase();

        for(int i = 0, j = 0; i < plaintext.length(); i++) {
            char current = plaintext.charAt(i);
            if(current < 'A' || current > 'Z')  //ignores spaces and other special characters
                continue;
            result += (char)((current + key.charAt(j) - 2 * 'A') % 26 + 'A');
            j = ++j % key.length();
        }
        return result;
    }

    /**
     * Decrypts the ciphertext using the supplied key
     * @param ciphertext    Text to be decrypted
     * @param key           Key to be used for decryption
     * @return  The decrypted text
     */
    static String decrypt(String ciphertext, final String key) {
        String result = "";
        ciphertext = ciphertext.toUpperCase();

        for(int i = 0, j = 0; i < ciphertext.length(); i++) {
            char current = ciphertext.charAt(i);
            if(current < 'A' || current > 'Z')  //ignores spaces and other special characters
                continue;
            result += (char)((current - key.charAt(i % key.length()) + 26) % 26 + 'A');
            j = ++j % key.length();
        }
        return result;
    }

    /**
     * Attempt to decipher the ciphertext without a key
     * First we must find the length of the key, then
     * we must discover the key by treating it as a series
     * of Caesar ciphers, their number being equal to the key length
     * @param ciphertext    The ciphertext we are trying to decipher
     */
    static void decipher(String ciphertext) {
        int keyLength = findKeyLength(ciphertext);
        if(keyLength == -1) {
            System.err.println("ERROR: Could not find key length");
            System.exit(1);
        }

        String deciphered = breakCipher(ciphertext, keyLength);
        System.out.println(deciphered);
    }


    /**
     * Attempt to find the length of the key that was
     * used to encrypt the ciphertext.
     * Uses Index of Coincidence analysis to do so
     * @param ciphertext    The encrypted text
     * @return  The suspected length of the key
     */
    private static int findKeyLength(String ciphertext) {
        //First find the length of the key
        double IOC = 0.0;
        int keyLength = -1;

        for(int i = 1; i <= MAX_KEY_LENGTH; i++) {
            String str = "";
            double tempIOC = 0.0;

            //Create substrings equal in number to key length with alternating characters
            for(int j = 0, k = 1; j < ciphertext.length(); j += i) {

                str += ciphertext.charAt(j);

                //Calculate IOC for each substring
                if(j + i >= ciphertext.length() && k != i) {
                    tempIOC += calculateIOC(str);
                    j = k++ - i;
                }
                else if(j + i >= ciphertext.length()){
                    tempIOC += calculateIOC(str);
                }
            }

            tempIOC /= i;

            if(tempIOC > IOC) {
                IOC = tempIOC;
                keyLength = i;
            }

        }

        return keyLength;
    }


    /**
     * Used to calculate the IOC of a given string of text
     * @param text    The text that will be tested
     * @return  The IOC of the text
     */
    private static double calculateIOC(String text) {
        int totalLetters = 0;
        int numerator = 0;
        int denominator = 0;
        double IOC;
        int letterCount[] = new int[26];

        for(int i = 0; i < letterCount.length; i++) {   //initialize elements to 0
            letterCount[i] = 0;
        }

        for(int i = 0; i < text.length(); i++) {
            letterCount[text.charAt(i) - 'A']++;
            totalLetters++;
        }

        for (int letter : letterCount) {
            numerator += (letter * (letter - 1));
        }

        denominator = (totalLetters * (totalLetters - 1));

        IOC = (double) numerator / (double) denominator;

        return IOC;
    }

    /**
     * Using the known keyLength we will analyze the ciphertext
     * using chi-squared analysis and attempt to derive the plaintext
     * @param ciphertext    The ciphertext to be analyzed
     * @param keyLength     Known key length
     * @return  The deciphered text
     */
    private static String breakCipher(String ciphertext, int keyLength) {
        //Initialize a list of strings
        List<String> strList = new ArrayList<>(keyLength);
        //Probability of each letter appearing in English
        double expected[] = {0.08167,0.01492,0.02782,0.04253,0.12702,
                0.02228,0.02015,0.06094,0.06966,0.00153,0.00772,
                0.04025,0.02406,0.06749,0.07507,0.01929,0.00095,
                0.05987,0.06327,0.09056,0.02758,0.00978, 0.02360,
                0.00150,0.01974,0.00074};

        //Decipher each character sequence
        for(int i = 0; i < keyLength; i++) {
            double lowChiSq = 99999.0;
            String bestShift = "";
            String str = "";
            for(int j = i; j < ciphertext.length(); j += keyLength) {
                str += ciphertext.charAt(j);
            }

            List<String> shifts = new ArrayList<>(26);
            for(int j = 0; j < 26; j++) {
                shifts.add(j, shift(str, j));
            }

            //Chi Sq calculation
            for(String s : shifts) {
                //Count occurrences of each character
                int letterCount[] = new int[26];
                for(int j = 0; j < s.length(); j++) {
                    letterCount[s.charAt(j) - 'A']++;
                }

                //Test occurrences against expected occurrences
                int chiSq = 0;
                for(int j = 0; j < 26; j++) {
                    double expCount = s.length() * expected[j];
                    chiSq += (Math.pow((letterCount[j] - expCount), 2) / expCount);
                }

                //If chiSq is lower (better) for this shift, save it
                if(chiSq < lowChiSq) {
                    lowChiSq = chiSq;
                    bestShift = s;
                }
            }
            strList.add(i, bestShift);
        }

        //Build the decrypted string from the saved sections
        StringBuilder sb = new StringBuilder(ciphertext.length());
        for(int i = 0; i < strList.get(0).length(); i++) {
            for(int j = 0; j < keyLength; j++) {
                if(strList.get(j).length() > i)
                    sb.append(strList.get(j).charAt(i));
            }
        }

        return sb.toString();
    }


    /**
     * Shifts the characters in the text by the shift value
     * Works exactly like a basic Caesar cipher
     * @param text  The text to be shifted
     * @param shift The amount by which we will shift each character
     * @return  The shifted text
     */
    private static String shift(String text, int shift) {
        String str = "";
        for(int k = 0; k < text.length(); k++) {
            char c = (char)(text.charAt(k) + shift);
            if(c <= 'Z')
                str += c;
            else
                str += (char)(c - 26);
        }
        return str;
    }
}
