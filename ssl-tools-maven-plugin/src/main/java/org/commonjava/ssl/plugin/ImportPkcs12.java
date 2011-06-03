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

package org.commonjava.ssl.plugin;

import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.commonjava.ssl.CertificateImporter;
import org.commonjava.ssl.SSLToolsException;

import java.io.File;

/**
 * Imports a client certificate file (in <a href="http://www.rsa.com/rsalabs/node.asp?id=2138">PKCS#12</a> format) into
 * a Java keystore file.
 * 
 * @goal import-client-cert
 */
public class ImportPkcs12
    extends AbstractSSLToolsMojo
{

    /**
     * File containing the client certificate in <a href="http://www.rsa.com/rsalabs/node.asp?id=2138">PKCS#12</a>
     * format.
     * 
     * @parameter expression="${import.certificate}"
     * @required
     */
    private File certificate;

    /**
     * Password for the client certificate file.
     * 
     * @parameter expression="${import.certpass}"
     */
    private String certpass;

    public void execute()
        throws MojoExecutionException, MojoFailureException
    {
        try
        {
            CertificateImporter importer =
                CertificateImporter.open( keystore, storepass.toCharArray() ).importClientCertificate( certificate,
                                                                                                       certpass.toCharArray() );

            if ( importer.isChanged() )
            {
                importer.save( keystore, storepass.toCharArray() );
            }
        }
        catch ( SSLToolsException e )
        {
            throw new MojoExecutionException( e.getMessage(), e );
        }
    }

    public File getCertificate()
    {
        return certificate;
    }

    public void setCertificate( File certificate )
    {
        this.certificate = certificate;
    }

    public String getCertpass()
    {
        return certpass;
    }

    public void setCertpass( String certpass )
    {
        this.certpass = certpass;
    }

}
