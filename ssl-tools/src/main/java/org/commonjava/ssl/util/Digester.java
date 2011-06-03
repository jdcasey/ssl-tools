/*
 * Copyright (c) 2011 Red Hat, Inc.
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see 
 * <http://www.gnu.org/licenses>.
 */

package org.commonjava.ssl.util;

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
