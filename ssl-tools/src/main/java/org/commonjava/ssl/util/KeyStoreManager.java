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

import static org.apache.commons.io.IOUtils.closeQuietly;

import org.commonjava.ssl.SSLToolsException;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;

public class KeyStoreManager
{

    public static final String DEFAULT_KEYSTORE_TYPE = KeyStore.getDefaultType();

    public static final String PKCS12_KEYSTORE_TYPE = "pkcs12";

    private static final String FS = File.separator;
    
    private KeyStoreManager(){}

    public static char[] getDefaultKeystorePassword()
    {
        return "changeit".toCharArray();
    }

    public static File getDefaultSourceKeystore()
    {
        File dir = new File( System.getProperty( "java.home" ) + FS + "lib" + FS + "security" );
        File targetKeystore = new File( dir, "jssecacerts" );
        File sourceKeystore = targetKeystore;

        if ( !sourceKeystore.isFile() )
        {
            sourceKeystore = new File( dir, "cacerts" );
        }

        return sourceKeystore;
    }

    public static File getDefaultTargetKeystore()
    {
        File dir = new File( System.getProperty( "java.home" ) + FS + "lib" + FS + "security" );
        File targetKeystore = new File( dir, "jssecacerts" );

        return targetKeystore;
    }

    public static void save( KeyStore keystore, File keystoreFile, char[] storepass )
        throws SSLToolsException
    {
        save( keystore, keystoreFile, storepass, false );
    }

    public static void save( KeyStore keystore, File keystoreFile, char[] storepass, boolean makeBackup )
        throws SSLToolsException
    {
        OutputStream out = null;
        try
        {
            if ( makeBackup && keystoreFile.exists() && !keystoreFile.isDirectory() )
            {
                File renamed = new File( keystoreFile.getAbsolutePath() + ".bak" );
                keystoreFile.renameTo( renamed );
            }

            out = new FileOutputStream( keystoreFile );
            keystore.store( out, storepass );
        }
        catch ( Exception e )
        {
            throw new SSLToolsException( "Failed to write keystore: %s", e, e.getMessage() );
        }
        finally
        {
            closeQuietly( out );
        }
    }

    public static KeyStore load( File keystoreFile, char[] storepass )
        throws SSLToolsException
    {
        return load( keystoreFile, storepass, DEFAULT_KEYSTORE_TYPE );
    }

    public static KeyStore load( File keystoreFile, char[] storepass, String keystoreType )
        throws SSLToolsException
    {
        InputStream in = null;
        try
        {
            in = new FileInputStream( keystoreFile );

            KeyStore keystore = KeyStore.getInstance( keystoreType );
            keystore.load( in, storepass );

            return keystore;
        }
        catch ( Exception e )
        {
            throw new SSLToolsException( "Failed to read keystore at: %s\nError: %s", e, keystoreFile, e.getMessage() );
        }
        finally
        {
            closeQuietly( in );
        }
    }

    public static KeyStore create()
        throws SSLToolsException
    {
        return create( DEFAULT_KEYSTORE_TYPE );
    }

    public static KeyStore create( String keystoreType )
        throws SSLToolsException
    {
        try
        {
            return KeyStore.getInstance( keystoreType );
        }
        catch ( KeyStoreException e )
        {
            throw new SSLToolsException( "Failed to create KeyStore instance: %s", e, e.getMessage() );
        }
    }

}
