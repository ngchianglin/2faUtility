/*
* MIT License
*
*Copyright (c) 2018 Ng Chiang Lin
*
*Permission is hereby granted, free of charge, to any person obtaining a copy
*of this software and associated documentation files (the "Software"), to deal
*in the Software without restriction, including without limitation the rights
*to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
*copies of the Software, and to permit persons to whom the Software is
*furnished to do so, subject to the following conditions:
*
*The above copyright notice and this permission notice shall be included in all
*copies or substantial portions of the Software.
*
*THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
*IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
*FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
*AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
*LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
*OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
*SOFTWARE.
*
*/

/*
 * Simple utility to generate a secret key for Google Authenticator Mobile App.
 * The secret key is printed as a base 32 format which can be entered into Google Authenticator Mobile App.
 * The hexadecimal string of the secret key is printed as well. 
 */

import java.security.SecureRandom;
import sg.nighthour.crypto.CryptoUtil;


public class GenerateOTPSecret {
	
	
	/**
	 * Encode input bytes into base32 string
	 * @param input
	 * @return the base32 string
	 */
	private static String encode32(byte[] input)
    {
        if ((input.length % 5) != 0)
        {// Input array has be divisible by 5
         // In base 32 ,every 5 bytes will encode to 8 characters
            return null;
        }

        char table[] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
                'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '2', '3', '4', '5', '6', '7' };

        int mask = 0xF8;
        byte tmp;

        int arrayindex = 0;

        StringBuilder ret = new StringBuilder();

        while (arrayindex < input.length)
        {
            tmp = input[arrayindex];

            // first byte
            int tindex = tmp & mask;
            tindex = tindex >>> 3;
            ret.append(table[tindex]);

            // 3 bits remain , borrows 2 bits from next byte
            tmp = (byte) ((input[arrayindex] << 5) | ((input[arrayindex + 1] & 0xff) >>> 3));
            // Need to & the next byte by 0xff to ensure that when it is cast to
            // int for the right shift operation
            // the additional 24 bits to its left are 0. Otherwise >>> will not
            // work properly.
            tindex = tmp & mask;
            tindex = tindex >>> 3;
            ret.append(table[tindex]);

            // 6 bits remain
            tmp = (byte) (input[arrayindex + 1] << 2);
            tindex = tmp & mask;
            tindex = tindex >>> 3;
            ret.append(table[tindex]);

            // 1 bit remain, borrows 4 bits from next byte
            tmp = (byte) ((input[arrayindex + 1] << 7) | ((input[arrayindex + 2] & 0xff) >>> 1));
            tindex = tmp & mask;
            tindex = tindex >>> 3;
            ret.append(table[tindex]);

            // 4 bits remain, borrows 1 bit from next byte
            tmp = (byte) ((input[arrayindex + 2] << 4) | ((input[arrayindex + 3] & 0xff) >>> 4));
            tindex = tmp & mask;
            tindex = tindex >>> 3;
            ret.append(table[tindex]);

            // 7bits remain
            tmp = (byte) (input[arrayindex + 3] << 1);
            tindex = tmp & mask;
            tindex = tindex >>> 3;
            ret.append(table[tindex]);

            // 2bits remain, borrows 3 bits from next byte
            tmp = (byte) ((input[arrayindex + 3] << 6) | ((input[arrayindex + 4] & 0xff) >>> 2));
            tindex = tmp & mask;
            tindex = tindex >>> 3;
            ret.append(table[tindex]);

            // 5bits remain
            tmp = (byte) (input[arrayindex + 4] << 3);
            tindex = tmp & mask;
            tindex = tindex >>> 3;
            ret.append(table[tindex]);

            arrayindex += 5;

        }

        return ret.toString();

    }
	
	
	public static void main(String[] args)
	{
		//Generate a 20 bytes random secret key
		SecureRandom rand = new SecureRandom();
        byte[] ret = new byte[20];
        rand.nextBytes(ret);
        
        String base32str = encode32(ret);
        
        //Pretty format the base32 String, change all to lowercase 
        //and display a space every 4 chars
        
        base32str = base32str.toLowerCase();
        StringBuilder buf = new StringBuilder(64);
        int count = 0;
        for(int i=0;i< base32str.length(); i++)
        {
        	buf.append(base32str.charAt(i));
        	count ++;
        	
        	if(i < 28 && count == 4)
        	{
        		buf.append(" ");
        		count = 0;
        	}
        	
        }
        
        System.out.println("The base32 encoded OTP secret key can be configured in the android");
        System.out.println("Google Authenticator application to generate time based one time password");
        System.out.println("OTP Secret Key in Hexadecimal : "  + CryptoUtil.byteArrayToHexString(ret));
        System.out.println("OTP Secret Key in base32 : " + buf.toString());
        
	}
	
	

}
