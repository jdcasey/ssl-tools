/*
 * Copyright 2011 Red Hat, Inc.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.commonjava.ssl.sec;

import org.commonjava.ssl.SSLToolsException;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public final class Digester
{

    private static final char[] HEXDIGITS = "0123456789abcdef".toCharArray();

    private MessageDigest digest;

    public Digester()
        throws SSLToolsException
    {
        try
        {
            digest = MessageDigest.getInstance( "SHA1" );
        }
        catch ( NoSuchAlgorithmException e )
        {
            throw new SSLToolsException( "Cannot initialize SHA1 message-digest: %s", e, e.getMessage() );
        }
    }

    public synchronized final Digest newDigest( byte[] data )
        throws SSLToolsException
    {
        digest.reset();
        return new Digest( digest.digest( data ) );
    }

    public static final class Digest
    {
        private final byte[] bytes;
        
        private transient String hexString;

        private Digest( byte[] bytes )
        {
            this.bytes = bytes;
        }

        public byte[] getDigested()
        {
            byte[] defensiveCopy = new byte[bytes.length];
            System.arraycopy( bytes, 0, defensiveCopy, 0, bytes.length );

            return defensiveCopy;
        }

        public synchronized String toString()
        {
            if ( hexString == null )
            {
                StringBuilder sb = new StringBuilder( bytes.length * 3 );
                for ( int i = 0; i < bytes.length; i++ )
                {
                    int b = bytes[i];
                    b &= 0xff;
                    sb.append( HEXDIGITS[b >> 4] );
                    sb.append( HEXDIGITS[b & 15] );
                    sb.append( ' ' );
                }
                
                hexString = sb.toString();
            }

            return hexString;
        }

        @Override
        public int hashCode()
        {
            final int prime = 31;
            int result = 1;
            result = prime * result + Arrays.hashCode( bytes );
            return result;
        }

        @Override
        public boolean equals( Object obj )
        {
            if ( this == obj )
                return true;
            if ( obj == null )
                return false;
            if ( getClass() != obj.getClass() )
                return false;
            Digest other = (Digest) obj;
            if ( !Arrays.equals( bytes, other.bytes ) )
                return false;
            return true;
        }

    }

}
