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
    
    public static String hex(int[] bytes) {
        StringBuilder result = new StringBuilder();
        for (int aByte : bytes) {
            result.append(String.format("%02x", aByte));
            
        }
        return result.toString();
    }
    
    public static String hex(byte[][] bytes){
        StringBuilder result = new StringBuilder();
        
        for (int i=0; i<4; i++){
            
            for (int j=0; j<4; j++){
                byte aByte = bytes[j][i];
                result.append(String.format("%02x", aByte));
            }
        }
        return result.toString();
    }
    
    

    public static void main(String[] args) {
        // TODO code application logic here

        AESAlgorithm aes = new AESAlgorithm(128);

        byte key[] = aes.createKey();

        System.out.println(hex(key));

        int subkeys[] = aes.createKeyExpansion(key);

        System.out.println(hex(subkeys));

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
