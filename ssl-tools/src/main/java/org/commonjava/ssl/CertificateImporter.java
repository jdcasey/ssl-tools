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

package org.commonjava.ssl;

import org.commonjava.ssl.util.Digester;
import org.commonjava.ssl.util.KeyStoreManager;
import org.commonjava.ssl.util.Logger;
import org.commonjava.ssl.util.SavingTrustManager;
import org.commonjava.ssl.util.Digester.Digest;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import java.io.File;
import java.io.IOException;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.security.Key;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

public class CertificateImporter
{

    private static final Logger LOGGER = new Logger( CertificateImporter.class );

    private final KeyStore keystore;

    private boolean changed = false;

    private CertificateImporter( KeyStore keystore )
    {
        this.keystore = keystore;
    }

    public CertificateImporter importClientCertificate( File clientCertFile, char[] certpass )
        throws SSLToolsException
    {
        if ( clientCertFile == null || !( clientCertFile.isFile() && clientCertFile.canRead() ) )
        {
            LOGGER.info( "Invalid client certificate file: %s. Cannot import.", clientCertFile );
            return this;
        }

        KeyStore pkcs12Keystore = KeyStoreManager.load( clientCertFile, certpass, KeyStoreManager.PKCS12_KEYSTORE_TYPE );

        try
        {
            for ( Enumeration<String> e = pkcs12Keystore.aliases(); e.hasMoreElements(); )
            {
                String alias = e.nextElement();

                if ( pkcs12Keystore.isKeyEntry( alias ) )
                {
                    LOGGER.info( "Adding key for: %s", alias );
                    Key key = pkcs12Keystore.getKey( alias, certpass );

                    Certificate[] chain = pkcs12Keystore.getCertificateChain( alias );
                    keystore.setKeyEntry( alias, key, certpass, chain );
                    changed = true;
                }
            }
        }
        catch ( KeyStoreException e )
        {
            throw new SSLToolsException( "Failed to add new keys to keystore: %s", e, e.getMessage() );
        }
        catch ( UnrecoverableKeyException e )
        {
            throw new SSLToolsException( "Failed to add new keys to keystore: %s", e, e.getMessage() );
        }
        catch ( NoSuchAlgorithmException e )
        {
            throw new SSLToolsException( "Failed to add new keys to keystore: %s", e, e.getMessage() );
        }

        return this;
    }

    public CertificateImporter importServerCertificates( String host, int port, File sourceKeystore,
                                                         char[] sourceStorepass, File targetKeystore,
                                                         char[] targetStorepass )
        throws SSLToolsException
    {
        SSLSocket socket;
        SSLContext context;
        SavingTrustManager tm;

        try
        {
            LOGGER.trace( "Setting up SSL..." );

            context = SSLContext.getInstance( "TLS" );

            TrustManagerFactory tmf = TrustManagerFactory.getInstance( TrustManagerFactory.getDefaultAlgorithm() );
            tmf.init( keystore );

            X509TrustManager defaultTrustManager = (X509TrustManager) tmf.getTrustManagers()[0];
            tm = new SavingTrustManager( defaultTrustManager );

            context.init( null, new TrustManager[] { tm }, null );

            SSLSocketFactory factory = context.getSocketFactory();

            LOGGER.trace( "Opening connection to %s:%d...", host, port );

            socket = (SSLSocket) factory.createSocket( host, port );
            socket.setSoTimeout( 10000 );
        }
        catch ( SocketException e )
        {
            throw new SSLToolsException( "Failed to initialize SSL socket: %s", e, e.getMessage() );
        }
        catch ( UnknownHostException e )
        {
            throw new SSLToolsException( "Unknown host: %s:%d", e, host, port );
        }
        catch ( IOException e )
        {
            throw new SSLToolsException( "Failed to initialize SSL socket: %s", e, e.getMessage() );
        }
        catch ( KeyManagementException e )
        {
            throw new SSLToolsException( "Failed to initialize SSL: %s", e, e.getMessage() );
        }
        catch ( NoSuchAlgorithmException e )
        {
            throw new SSLToolsException( "Failed to initialize SSL: %s", e, e.getMessage() );
        }
        catch ( KeyStoreException e )
        {
            throw new SSLToolsException( "Failed to initialize SSL: %s", e, e.getMessage() );
        }

        SSLException sslException = null;
        try
        {
            LOGGER.trace( "Starting SSL handshake..." );

            socket.startHandshake();
            socket.close();

            LOGGER.debug( "All certificates are already trusted. Nothing to do." );
            return this;
        }
        catch ( SSLException e )
        {
            sslException = e;
            LOGGER.debug( "Some SSL certificates appear to be missing. Adding missing certificates..." );
        }
        catch ( IOException e )
        {
            throw new SSLToolsException( "I/O error performing SSL handshake for: %s:%d. Error: %s", e, host, port,
                                         e.getMessage() );
        }

        X509Certificate[] chain = tm.getChain();
        if ( chain == null )
        {
            throw new SSLToolsException( "Could not retrieve certificate chain: %s", sslException, sslException.getMessage() );
        }

        Digester digester = new Digester();

        int hostPrefixIdx = 1;
        String hostPrefix = host;

        Map<Digest, String> existingCertificates = new HashMap<Digest, String>();

        try
        {
            for ( Enumeration<String> e = keystore.aliases(); e.hasMoreElements(); )
            {
                String alias = (String) e.nextElement();
                if ( alias.startsWith( hostPrefix ) )
                {
                    hostPrefix = hostPrefixIdx + "@" + host;
                    hostPrefixIdx++;
                }

                if ( alias != null && keystore.isCertificateEntry( alias ) )
                {
                    Certificate cert = keystore.getCertificate( alias );

                    Digest digest = digester.newDigest( cert.getEncoded() );
                    existingCertificates.put( digest, alias );
                }
            }
        }
        catch ( CertificateEncodingException e )
        {
            throw new SSLToolsException( "Failed to scan keystore for existing certificates. Error: %s", e,
                                         e.getMessage() );
        }
        catch ( KeyStoreException e )
        {
            throw new SSLToolsException( "Failed to scan keystore for existing certificates. Error: %s", e,
                                         e.getMessage() );
        }

        LOGGER.debug( "Server sent %d certificate(s):", chain.length );

        for ( int i = 0, certCounter = 0; i < chain.length; i++ )
        {
            X509Certificate cert = chain[i];

            LOGGER.debug( " %d Subject: %s\n    Issuer: %s", ( i + 1 ), cert.getSubjectDN(), cert.getIssuerDN() );

            Digest digest;
            try
            {
                digest = digester.newDigest( cert.getEncoded() );
            }
            catch ( Exception e )
            {
                throw new SSLToolsException( "Failed to get encoded form of certificate: %s", e, e.getMessage() );
            }

            LOGGER.debug( "   sha1: %s", digest );

            String name = existingCertificates.get( digest );
            if ( name != null )
            {
                LOGGER.debug( "Keystore already contains certificate with this SHA1 hash, under alias: '%s' ...Skipping.",
                              name );
                continue;
            }

            String alias = hostPrefix;
            while ( existingCertificates.containsValue( alias ) )
            {
                alias += "-" + ( ++certCounter );
            }

            try
            {
                existingCertificates.put( digest, alias );
                keystore.setCertificateEntry( alias, cert );
                changed = true;
            }
            catch ( KeyStoreException e )
            {
                throw new SSLToolsException( "Failed to add certificate to keystore: %s. Error: %s", e, alias,
                                             e.getMessage() );
            }

            LOGGER.info( "Added certificate to keystore using alias: '%s'", alias );
        }

        return this;
    }

    public boolean isChanged()
    {
        return changed;
    }

    public static CertificateImporter open( File keystoreFile, char[] storepass )
        throws SSLToolsException
    {
        if ( keystoreFile == null )
        {
            throw new SSLToolsException( "Invalid keystore file: %s. Cannot import.", keystoreFile );
        }

        KeyStore ks = KeyStoreManager.load( keystoreFile, storepass );
        return new CertificateImporter( ks );
    }

    public static CertificateImporter openOrCreate( File keystoreFile, char[] storepass )
        throws SSLToolsException
    {
        if ( keystoreFile == null )
        {
            throw new SSLToolsException( "Invalid keystore file: %s. Cannot import.", keystoreFile );
        }

        KeyStore ks;
        if ( !keystoreFile.exists() )
        {
            ks = KeyStoreManager.create();
        }
        else
        {
            ks = KeyStoreManager.load( keystoreFile, storepass );
        }

        return new CertificateImporter( ks );
    }

    public void save( File keystoreFile, char[] storepass )
        throws SSLToolsException
    {
        KeyStoreManager.save( keystore, keystoreFile, storepass );
    }

    public void save( File keystoreFile, char[] storepass, boolean makeBackup )
        throws SSLToolsException
    {
        KeyStoreManager.save( keystore, keystoreFile, storepass, makeBackup );
    }

}
