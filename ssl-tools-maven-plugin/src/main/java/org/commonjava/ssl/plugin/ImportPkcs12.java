/*
 *  Copyright (C) 2011 John Casey.
 *  
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *  
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.commonjava.ssl.plugin;

import org.apache.maven.plugin.Mojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugin.logging.Log;
import org.commonjava.ssl.SSLToolsException;
import org.commonjava.ssl.in.CertificateImporter;

import java.io.File;

/**
 * Imports a client certificate file (in <a href="http://www.rsa.com/rsalabs/node.asp?id=2138">PKCS#12</a>
 * format) into a Java keystore file.
 * 
 * @goal import-client-cert
 */
public class ImportPkcs12
    implements Mojo
{

    private Log log;
    
    /**
     * Keystore file into which the client certificate should be imported.
     * 
     * @parameter expression="${import.keystore}" default-value="${java.home}/lib/security/cacerts"
     */
    private File keystore;
    
    /**
     * File containing the client certificate in <a href="http://www.rsa.com/rsalabs/node.asp?id=2138">PKCS#12</a>
     * format.
     * 
     * @parameter expression="${import.certificat}"
     * @required
     */
    private File certificate;
    
    /**
     * Password for the Keystore file.
     * 
     * @parameter expression="${import.storepass}" default="changeit"
     */
    private String storepass;
    
    /**
     * Password for the client certificate file.
     * 
     * @parameter expression="${import.certpass}"
     */
    private String certpass;

    @Override
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

    @Override
    public Log getLog()
    {
        return log;
    }

    @Override
    public void setLog( Log log )
    {
        this.log = log;
    }

}
