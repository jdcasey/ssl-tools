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

import static org.apache.commons.io.IOUtils.closeQuietly;

import org.commonjava.ssl.SSLToolsException;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;

public class KeyStoreManager
{
    
    public static final String DEFAULT_KEYSTORE_TYPE = KeyStore.getDefaultType();
    
    public static final String PKCS12_KEYSTORE_TYPE = "pkcs12";

    private static final String FS = File.separator;

    private char[] storepass;

    private File keystoreFile;

    private KeyStore keystore;

    private String keystoreType;

    public KeyStoreManager( final File keystoreFile, final char[] storepass )
        throws SSLToolsException
    {
        this.keystoreFile = keystoreFile;
        this.storepass = storepass == null ? null : defensiveCopy( storepass );
        this.keystoreType = KeyStore.getDefaultType();

        load();
    }

    public KeyStoreManager( final File keystoreFile, final String keystoreType, final char[] storepass )
        throws SSLToolsException
    {
        this.keystoreFile = keystoreFile;
        this.keystoreType = keystoreType;
        this.storepass = storepass == null ? null : defensiveCopy( storepass );
        this.keystoreType = KeyStore.getDefaultType();

        load();
    }
    
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
    
    public void save()
        throws SSLToolsException
    {
        save( false );
    }

    public void save( boolean makeBackup )
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

    private void load()
        throws SSLToolsException
    {
        InputStream in = null;
        try
        {
            in = new FileInputStream( keystoreFile );

            keystore = KeyStore.getInstance( keystoreType );
            keystore.load( in, storepass );
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

    public KeyStore getKeystore()
    {
        return keystore;
    }

    public char[] getStorepass()
    {
        return defensiveCopy( storepass );
    }

    public void setStorepass( char[] storepass )
    {
        if ( storepass == null )
        {
            this.storepass = null;
        }
        else
        {
            this.storepass = defensiveCopy( storepass );
        }
    }

    public void setKeystoreFile( File sourceKeystore )
    {
        this.keystoreFile = sourceKeystore;
    }

    private char[] defensiveCopy( char[] pass )
    {
        char[] defensiveCopy = new char[pass.length];
        System.arraycopy( pass, 0, defensiveCopy, 0, pass.length );

        return defensiveCopy;
    }

    public String getKeystoreType()
    {
        return keystoreType;
    }

    public void setKeystoreType( String keystoreType )
    {
        this.keystoreType = keystoreType;
    }

    public File getKeystoreFile()
    {
        return keystoreFile;
    }

}
