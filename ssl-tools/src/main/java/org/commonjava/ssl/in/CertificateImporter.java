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

package org.commonjava.ssl.in;

import org.commonjava.ssl.SSLToolsException;
import org.commonjava.ssl.sec.Digester;
import org.commonjava.ssl.sec.KeyStoreManager;
import org.commonjava.ssl.sec.Digester.Digest;
import org.commonjava.util.logging.Logger;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import java.io.File;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

public class CertificateImporter
{
    
    private static final Logger LOGGER = new Logger( CertificateImporter.class );
    
    public void importClientCertificate( File clientCertFile, char[] certpass, File keystoreFile, char[] storepass )
        throws SSLToolsException
    {
        KeyStoreManager target = new KeyStoreManager( keystoreFile, storepass );
        KeyStore targetKeystore = target.getKeystore();
        
        KeyStoreManager pkcs = new KeyStoreManager( clientCertFile, KeyStoreManager.PKCS12_KEYSTORE_TYPE, certpass );
        KeyStore pkcs12Keystore = pkcs.getKeystore();

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
                    targetKeystore.setKeyEntry( alias, key, storepass, chain );
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
        
        target.save();
    }
    
    public void importServerCertificates( String host, int port, File sourceKeystore, char[] storepass,
                                          File targetKeystore )
        throws SSLToolsException
    {
        KeyStoreManager ksm = new KeyStoreManager( sourceKeystore, storepass );
        KeyStore ks = ksm.getKeystore();

        SSLSocket socket;
        SSLContext context;
        SavingTrustManager tm;

        try
        {
            LOGGER.trace( "Setting up SSL..." );

            context = SSLContext.getInstance( "TLS" );

            TrustManagerFactory tmf = TrustManagerFactory.getInstance( TrustManagerFactory.getDefaultAlgorithm() );
            tmf.init( ks );

            X509TrustManager defaultTrustManager = (X509TrustManager) tmf.getTrustManagers()[0];
            tm = new SavingTrustManager( defaultTrustManager );

            context.init( null, new TrustManager[] { tm }, null );

            SSLSocketFactory factory = context.getSocketFactory();

            LOGGER.trace( "Opening connection to %s:%d...", host, port );

            socket = (SSLSocket) factory.createSocket( host, port );
            socket.setSoTimeout( 10000 );
        }
        catch ( Exception e )
        {
            IllegalStateException error = new IllegalStateException( "Failed to initialize SSL", e );

            throw error;
        }

        SSLException sslException = null;
        try
        {
            LOGGER.trace( "Starting SSL handshake..." );

            socket.startHandshake();
            socket.close();

            LOGGER.debug( "All certificates are already trusted. Nothing to do." );
            return;
        }
        catch ( SSLException e )
        {
            sslException = e;
            LOGGER.debug( "Some SSL certificates appear to be missing. Adding missing certificates..." );
        }
        catch ( IOException e )
        {
            IllegalStateException error = new IllegalStateException( "I/O error performing SSL handshake." );
            error.initCause( e );

            throw error;
        }

        X509Certificate[] chain = tm.getChain();
        if ( chain == null )
        {
            LOGGER.error( "Could not obtain server certificate chain.\nException from SSL handshake was: %s",
                                                                              sslException, sslException.getMessage() );
            sslException.printStackTrace( System.out );
            return;
        }

        Digester digester = new Digester();

        int hostPrefixIdx = 1;
        String hostPrefix = host;

        Map<Digest, String> existingCertificates = new HashMap<Digest, String>();

        try
        {
            for ( Enumeration<String> e = ks.aliases(); e.hasMoreElements(); )
            {
                String alias = (String) e.nextElement();
                if ( alias.startsWith( hostPrefix ) )
                {
                    hostPrefix = hostPrefixIdx + "@" + host;
                    hostPrefixIdx++;
                }

                if ( alias != null && ks.isCertificateEntry( alias ) )
                {
                    Certificate cert = ks.getCertificate( alias );

                    Digest digest = digester.newDigest( cert.getEncoded() );
                    existingCertificates.put( digest, alias );
                }
            }
        }
        catch ( Exception e )
        {
            IllegalStateException error =
                new IllegalStateException( "Failed to scan keystore for existing certificates" );
            error.initCause( e );

            throw error;
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
                LOGGER.debug( "Keystore already contains certificate with this SHA1 hash, under alias: '%s' ...Skipping.", name );
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
                ks.setCertificateEntry( alias, cert );
            }
            catch ( KeyStoreException e )
            {
                IllegalStateException error = new IllegalStateException( "Failed to add certificate to keystore" );
                error.initCause( e );

                throw error;
            }

            LOGGER.info( "Added certificate to keystore using alias: '%s'", alias );
        }
        
        ksm.setKeystoreFile( targetKeystore );
        ksm.save();

    }

}
