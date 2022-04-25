/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package cryptography_project;

import java.util.ArrayList;


import static cryptography_project.AESProject.hex;
/**
 *
 * @author lenovo
 */
public class AESAlgorithm {

    public static final int KEY_SIZE_128 = 128;
    public static final int KEY_SIZE_192 = 192;
    public static final int KEY_SIZE_256 = 256;

    public static final int NB_VALUE = 4;

    protected int Nk = 4; //Number of word vectors in the initial Key
    protected int Nb = NB_VALUE; //Number of word vectors in a subkey (always 4)
    protected int Nr = 10; //Number of Rounds


    public static boolean isValidKeySize(int keySize) {

        //A Function to check if the key size provided by the user is valid or not
        return keySize == AESAlgorithm.KEY_SIZE_128
                || keySize == AESAlgorithm.KEY_SIZE_192
                || keySize == AESAlgorithm.KEY_SIZE_256;

    }

    public int getNk() {
        return Nk;
    }

    public int getNb() {
        return Nb;
    }

    public int getNr() {
        return Nr;
    }

    private AESAlgorithm() {
    }

    public AESAlgorithm(int iBlockLength) {

        //Setting Up the parameter when we call the constructor.
        switch (iBlockLength) {
            case KEY_SIZE_128:
            Nk = 4;
            Nb = 4;
            Nr = 10;
            break;
        case KEY_SIZE_192:
            Nk = 6;
            Nb = 4;
            Nr = 12;
            break;
        case KEY_SIZE_256:
            Nk = 8;
            Nb = 4;
            Nr = 14;
            break;
            default:
            throw new java.lang.UnsupportedOperationException(
                    "key length can only be:128, 192 or 256");
        }

    }

    private static byte getBit(byte value, int i) {
        final byte bMasks[] = {(byte) 0x01, (byte) 0x02, (byte) 0x04,
            (byte) 0x08, (byte) 0x10, (byte) 0x20,
            (byte) 0x40, (byte) 0x80};
        byte bBit = (byte) (value & bMasks[i]);
        return (byte) ((byte) (bBit >> i) & (byte) 0x01);
    }

    private static byte xtime(byte value) {
        int iResult;
        iResult = (int) (value & 0x000000ff) * 02;
        return (byte) (((iResult & 0x100) != 0) ? iResult ^ 0x11b : iResult);
    }

    private static byte finiteMultiplication(int v1, int v2) {
        return finiteMultiplication((byte) v1, (byte) v2);
    }

    private static byte finiteMultiplication(byte v1, byte v2) {
        byte bTemps[] = new byte[8];
        byte bResult = 0;
        bTemps[0] = v1;
        for (int i = 1; i < bTemps.length; i++) {
            bTemps[i] = xtime(bTemps[i - 1]);
        }
        for (int i = 0; i < bTemps.length; i++) {
            if (getBit(v2, i) != 1) {
                bTemps[i] = 0;
            }
            bResult ^= bTemps[i];
        }
        return bResult;
    }

    private static byte[][] subBytes(byte state[][]) {
        for (byte[] state1 : state) {
            for (int j = 0; j < state1.length; j++) {
                state1[j] = sboxTransform(state1[j]);
            }
        }
        return state;
    }

    private static byte sboxTransform(byte value) {
        byte bUpper, bLower;
        bUpper = (byte) ((byte) (value >> 4) & 0x0f);
        bLower = (byte) (value & 0x0f);
        return AESData.sbox[bUpper][bLower];
    }

    private byte[][] shiftRows(byte state[][]) {
        byte stateNew[][] = new byte[state.length][state[0].length];
        // r=0 is not shifted
        stateNew[0] = state[0];
        for (int r = 1; r < state.length; r++) {
            for (int c = 0; c < state[r].length; c++) {
                stateNew[r][c] = state[r][(c + r) % Nb];
            }
        }

        return stateNew;
    }


    private byte[][] mixColumns(byte state[][]) {
        byte stateNew[][] = new byte[state.length][state[0].length];
        for (int c = 0; c < Nb; c++) {
            stateNew[0][c] = xor4Bytes(finiteMultiplication(state[0][c], 0x02),
                    finiteMultiplication(state[1][c], 0x03),
                    state[2][c], state[3][c]);
            stateNew[1][c] = xor4Bytes(state[0][c],
                    finiteMultiplication(state[1][c], 0x02),
                    finiteMultiplication(state[2][c], 0x03),
                    state[3][c]);
            stateNew[2][c] = xor4Bytes(state[0][c], state[1][c],
                    finiteMultiplication(state[2][c], 0x02),
                    finiteMultiplication(state[3][c], 0x03));
            stateNew[3][c] = xor4Bytes(finiteMultiplication(state[0][c], 0x03),
                    state[1][c], state[2][c],
                    finiteMultiplication(state[3][c], 0x02));
        }
        return stateNew;
    }

    private byte xor4Bytes(byte b1, byte b2, byte b3, byte b4) {
        byte bResult = 0;
        bResult ^= b1;
        bResult ^= b2;
        bResult ^= b3;
        bResult ^= b4;
        return bResult;
    }

    private byte getByte(int value, int iByte) {
        return (byte) ((value >>> (iByte * 8)) & 0x000000ff);
        // iByte is the byte number of value
        // value = |byte3|byte2|byte1|byte0|
    }

    private byte[][] addRoundKey(byte state[][], int w[], int l) {
        byte stateNew[][] = new byte[state.length][state[0].length];
        for (int c = 0; c < Nb; c++) {
            stateNew[0][c] = (byte) (state[0][c] ^ getByte(w[l + c], 3));
            stateNew[1][c] = (byte) (state[1][c] ^ getByte(w[l + c], 2));
            stateNew[2][c] = (byte) (state[2][c] ^ getByte(w[l + c], 1));
            stateNew[3][c] = (byte) (state[3][c] ^ getByte(w[l + c], 0));
        }
        return stateNew;
    }

    private static int subWord(int word) {
        int newWord = 0;
        newWord ^= (int) sboxTransform((byte) (word >>> 24)) & 0x000000ff;
        newWord <<= 8;

        newWord ^= (int) sboxTransform((byte) ((word & 0xff0000) >>> 16))
                & 0x000000ff;
        newWord <<= 8;

        newWord ^= (int) sboxTransform((byte) ((word & 0xff00) >>> 8))
                & 0x000000ff;
        newWord <<= 8;

        newWord ^= (int) sboxTransform((byte) (word & 0xff)) & 0x000000ff;

        return newWord;
    }

    private static int rotWord(int word) {
        return (word << 8) ^ ((word >> 24) & 0x000000ff);
    }

    private static int toWord(byte b1, byte b2, byte b3, byte b4) {
        int word = 0;
        word ^= ((int) b1) << 24;

        word ^= (((int) b2) & 0x000000ff) << 16;

        word ^= (((int) b3) & 0x000000ff) << 8;

        word ^= (((int) b4) & 0x000000ff);
        return word;
    }

    public void keyExpansion(byte key[], int w[]) {

        int iTemp = 0;
        int i = 0;

        while (i < Nk) {
            w[i] = toWord(key[4 * i], key[4 * i + 1], key[4 * i + 2],
                    key[4 * i + 3]);
            i++;
        }

        i = Nk;

        while (i < Nb * (Nr + 1)) {
            iTemp = w[i - 1];
            if (i % Nk == 0) {
                iTemp = subWord(rotWord(iTemp)) ^ AESData.Rcon[i / Nk];
            } else if (Nk > 6 && i % Nk == 4) {
                iTemp = subWord(iTemp);
            } // end if
            w[i] = w[i - Nk] ^ iTemp;
            i++;
        } // end while
    }

    public int[] createKeyExpansion(byte key[]) {
        int w[] = new int[Nb * (Nr + 1)];
        keyExpansion(key, w);
        return w;
    }

    public byte[] createKey() {
        byte key[] = new byte[4 * Nk];
        java.util.Random rndGen = new java.util.Random();
        rndGen.nextBytes(key);
        return key;
    }
    
    public ArrayList<byte[][]> cipher(byte bytesMessage[][], int wordsKeyExpansion[]) {
        byte state[][] = new byte[4][Nb];
        ArrayList<byte[][]> arrayOfStates = new ArrayList<>();
        state = bytesMessage;
        int n_of_col = bytesMessage[0].length;
//        System.out.println(n_of_col+"  col");
        int last_round_of_block =1;
        state = addRoundKey(state, wordsKeyExpansion, 0);
        
        arrayOfStates.add(state);
        
        for (int round = 1; round <= Nr - 1; round++) {
            
            state = subBytes(state);
            
            state = shiftRows(state);
           
            state = mixColumns(state);
            
            state = addRoundKey(state, wordsKeyExpansion, round * Nb);
            
            arrayOfStates.add(state);
        }
        
        state = subBytes(state);
        
        state = shiftRows(state);
        
        state = addRoundKey(state, wordsKeyExpansion, Nr * Nb);
        
        arrayOfStates.add(state);
//        System.out.println(arrayOfStates.get(last_round_of_block*10)+"1 block");
        return arrayOfStates;
    }

    public ArrayList<byte[][]> cipher_block(byte bytesMessage[][], int wordsKeyExpansion[]) {
        byte state[][] = new byte[4][Nb];
        ArrayList<byte[][]> arrayOfStates  = new ArrayList<>();
        ArrayList<byte[][]> arrayOfStates1 = new ArrayList<>();
        int n_of_col = bytesMessage[0].length;
//        System.out.println(n_of_col+" col");
        int last_round_of_block = 0;
        for (int c=0; c<n_of_col ;c+=4 ){
           last_round_of_block+=1;
            for (int i = 0; i < 4; i++) {
                int c_i = i+c;
                for (int j = 0; j < 4; j++) {
                    state[j][i] = bytesMessage[j][c_i];
                    System.out.println(state[j][i]+" "+i+" "+j+" "+c_i);
                }
            }
//        System.out.println(state[3][3]+"  c_i");
        
        state = addRoundKey(state, wordsKeyExpansion, 0);
        
        arrayOfStates.add(state);
        
        for (int round = 1; round <= Nr - 1; round++) {
            
            state = subBytes(state);
            
            state = shiftRows(state);
           
            state = mixColumns(state);
            
            state = addRoundKey(state, wordsKeyExpansion, round * Nb);
            
            arrayOfStates.add(state);
        }
        
        state = subBytes(state);
        
        state = shiftRows(state);
        
        state = addRoundKey(state, wordsKeyExpansion, Nr * Nb);
        
        arrayOfStates.add(state);
//        System.out.println(hex(arrayOfStates.get(last_round_of_block*10))+"");
        
     } 
        System.out.println(hex(arrayOfStates.get(1*10))+"");
        return arrayOfStates;
    }
    
    
    
    
    //Here we start with functions related to decryption
    
    
    private byte[][] invShiftRows(byte state[][]) {
        byte stateNew[][] = new byte[state.length][state[0].length];
        // r=0 is not shifted
        stateNew[0] = state[0];
        for (int r = 1; r < state.length; r++)
            for (int c = 0; c < state[r].length; c++)
                stateNew[r][(c + r) % Nb] = state[r][c];

        return stateNew;
    }

    private static byte[][] invSubBytes(byte state[][]) {
        for (byte[] state1 : state) {
            for (int j = 0; j < state1.length; j++) {
                state1[j] = invSboxTransform(state1[j]);
            }
        }
        return state;
    }

    private static byte invSboxTransform(byte value) {
        byte bUpper = 0, bLower = 0;
        bUpper = (byte) ((byte) (value >> 4) & 0x0f);
        bLower = (byte) (value & 0x0f);
        return AESData.sboxInv[bUpper][bLower];
    }

    private byte[][] invMixColumns(byte state[][]) {
        byte stateNew[][] = new byte[state.length][state[0].length];
        for (int c = 0; c < Nb; c++) {
            stateNew[0][c] = xor4Bytes(finiteMultiplication(state[0][c], 0x0e),
                                       finiteMultiplication(state[1][c], 0x0b),
                                       finiteMultiplication(state[2][c], 0x0d),
                                       finiteMultiplication(state[3][c], 0x09));
            stateNew[1][c] = xor4Bytes(finiteMultiplication(state[0][c], 0x09),
                                       finiteMultiplication(state[1][c], 0x0e),
                                       finiteMultiplication(state[2][c], 0x0b),
                                       finiteMultiplication(state[3][c], 0x0d));
            stateNew[2][c] = xor4Bytes(finiteMultiplication(state[0][c], 0x0d),
                                       finiteMultiplication(state[1][c], 0x09),
                                       finiteMultiplication(state[2][c], 0x0e),
                                       finiteMultiplication(state[3][c], 0x0b));
            stateNew[3][c] = xor4Bytes(finiteMultiplication(state[0][c], 0x0b),
                                       finiteMultiplication(state[1][c], 0x0d),
                                       finiteMultiplication(state[2][c], 0x09),
                                       finiteMultiplication(state[3][c], 0x0e));
        }
        return stateNew;

    }
    
    public ArrayList<byte[][]> invCipher(byte bytesMessage[][], int wordsKeyExpansion[]) {
        
        ArrayList<byte[][]> arrayOfStates = new ArrayList<>();
        byte state[][] = new byte[4][Nb];
        state = bytesMessage;
        
        state = addRoundKey(state, wordsKeyExpansion, Nr * Nb);
        
        arrayOfStates.add(state);
        for (int round = (Nr - 1); round >= 1; round--) {
           
            state = invShiftRows(state);
            
            state = invSubBytes(state);
            
            state = addRoundKey(state, wordsKeyExpansion, round * Nb);
            
            state = invMixColumns(state);
            
            arrayOfStates.add(state);
        }
        state = invShiftRows(state);
        
        state = invSubBytes(state);
        
        state = addRoundKey(state, wordsKeyExpansion, 0);
        
        arrayOfStates.add(state);
        return arrayOfStates;
    }

}
