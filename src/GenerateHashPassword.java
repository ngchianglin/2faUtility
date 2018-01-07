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

/**
 * Simple utility to generate a PBKDF2 password. 
 * The password and salt are output as hexadecimal string. 
 */

import java.io.Console;

import sg.nighthour.crypto.CryptoUtil;

public class GenerateHashPassword
{

    public static void main(String[] args)
    {
        char[] password = null;
       
        Console con = System.console();

        if (con == null)
        {
            System.err.println("Unable to get system console");
            System.exit(1);
        }

        password = con.readPassword("%s", "Enter password:");

        if (password == null)
        {
            System.err.println("Unable to get password");
            System.exit(1);
        }

        byte[] salt = CryptoUtil.generateRandomBytes(CryptoUtil.SALT_SIZE);
        byte[] derivekey = CryptoUtil.getPasswordKey(password, salt, CryptoUtil.PBE_ITERATION);

        String saltstring = CryptoUtil.byteArrayToHexString(salt);
        String keystring = CryptoUtil.byteArrayToHexString(derivekey);

        System.out.println("Password key : " + keystring);
        System.out.println("Salt : " + saltstring);

    }

}
