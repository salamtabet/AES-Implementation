/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Main.java to edit this template
 */
package cryptography_project;

import java.util.ArrayList;
import java.util.Arrays;

/**
 *
 * @author lenovo
 */
public class AESProject {

    /**
     * @param args the command line arguments
     */
    public static String hex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte aByte : bytes) {
            result.append(String.format("%02x", aByte));

        }
        return result.toString();
    }

    public static byte[] intToByteArray(int value) {
        return new byte[]{
            (byte) (value >>> 24),
            (byte) (value >>> 16),
            (byte) (value >>> 8),
            (byte) (value)
        };
    }

    public static String hex(int[] ints) {
        StringBuilder result = new StringBuilder();
        for (int aint : ints) {
            byte[] bytes = intToByteArray(aint);
            for (byte aByte : bytes) {
                result.append(String.format("%02x", aByte));
            }
        }
        return result.toString();
    }

    public static String hex(byte[][] bytes) {
        StringBuilder result = new StringBuilder();

        for (int i = 0; i < 4; i++) {

            for (int j = 0; j < 4; j++) {
                byte aByte = bytes[j][i];
                result.append(String.format("%02x", aByte));
            }
        }
        return result.toString();
    }

    public static byte[][] hexToByte(String hex) {
        byte[][] bytes = new byte[4][4];
        int ind = 0;
        for (int i = 0; i < 4; i++) {
            ind = 0;
            for (int j = 0; j < 4; j++) {
                bytes[j][i] = (byte) ((Character.digit(hex.charAt(i * 8 + ind), 16) << 4)
                        + Character.digit(hex.charAt(i * 8 + ind + 1), 16));
                ind += 2;
            }
        }
        return bytes;
    }

    public static byte[] hexToByte2(String hex, int size) {
        byte[] bytes = new byte[size];
        int ind = 0;
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) ((Character.digit(hex.charAt(ind), 16) << 4)
                    + Character.digit(hex.charAt(ind + 1), 16));
            ind += 2;
        }
        return bytes;
    }

    public static void main(String[] args) {
        // TODO code application logic here

        AESAlgorithm aes = new AESAlgorithm(128);

        byte key[] = aes.createKey();

        System.out.println(hex(key));

        int subkeys[] = aes.createKeyExpansion(key);

        System.out.println(hex(subkeys));
        System.out.println((hex(subkeys)).length());

        byte bytesMessage[][] = {{(byte) 0x21, (byte) 0x7c, (byte) 0x12, (byte) 0x55},
        {(byte) 0x21, (byte) 0x7c, (byte) 0x12, (byte) 0x55},
        {(byte) 0x21, (byte) 0x7c, (byte) 0x12, (byte) 0x55},
        {(byte) 0x21, (byte) 0x7c, (byte) 0x12, (byte) 0x55}
        };

        System.out.println(hex(bytesMessage));

        ArrayList<byte[][]> a = aes.cipher(bytesMessage, subkeys);

        System.out.println(hex(a.get(10)));

        ArrayList<byte[][]> b = aes.invCipher(a.get(10), subkeys);
        System.out.println(hex(b.get(10)));

    }

}
