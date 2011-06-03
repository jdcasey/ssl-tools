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

import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.project.MavenProject;
import org.commonjava.ssl.SSLToolsException;
import org.commonjava.ssl.in.CertificateImporter;

import java.io.File;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Imports one or more server SSL certificates (usually self-signed, or this wouldn't be necessary) into a Java keystore
 * file. If the <code>servers</code> parameter isn't set, this goal will scan all available repositories (from
 * <code>repositories</code>, <code>pluginRepositories</code>, <code>distributionManagement</code>, etc.) for
 * certificates it can import.
 * 
 * @goal import-server-cert
 */
public class ImportServerCert
    extends AbstractKeystoreMojo
{

    /**
     * Source Keystore file, from which to read certificates that have already been imported.
     * 
     * @parameter expression="${import.source-keystore}" default-value="${java.home}/lib/security/cacerts"
     */
    private File sourceKeystore;

    /**
     * Password for the Keystore file.
     * 
     * @parameter expression="${import.source-storepass}"
     */
    private String sourceStorepass;
    
    /**
     * List of servers whose certificates should be imported, of the format: <code>www.host.name[:port]</code>.
     * 
     * @parameter
     */
    private List<String> servers;
    
    /**
     * Servers to import when calling this goal from the command line directly. This is a comma-delimited
     * list, of the format <code>www.host.name[:port]</code>.
     * 
     * @parameter expression="${import.servers}"
     */
    private String importServers;
    
    /**
     * @parameter default-value="${project}"
     * @readonly
     */
    private MavenProject project;
    
    /**
     * @parameter default-value="${session}"
     * @readonly
     */
    private MavenSession session;
    
    private CertificateImporter importer;

    @Override
    public void execute()
        throws MojoExecutionException, MojoFailureException
    {
        if ( sourceKeystore == null )
        {
            sourceKeystore = keystore;
            sourceStorepass = storepass;
        }
        
        try
        {
            importer = CertificateImporter.openOrCreate( sourceKeystore, sourceStorepass.toCharArray() );
        }
        catch ( SSLToolsException e )
        {
            throw new MojoExecutionException( "Cannot open Certificate Importer: " + e.getMessage(), e );
        }
        
        Map<String, SSLToolsException> errors = new LinkedHashMap<String, SSLToolsException>();
        
        if ( importServers != null )
        {
            String[] servers = importServers.split( "\\s*,\\s*" );
            importAll( Arrays.asList( servers ), errors );
        }
        
        if ( servers != null )
        {
            importAll( servers, errors );
        }
        
        if (importServers == null && servers == null )
        {
            // TODO: Get the repositories, pluginRepositories, and distributionManagement repos, and use those...
//            session.get
        }

        if ( importer != null && importer.isChanged() )
        {
            try
            {
                importer.save( keystore, storepass.toCharArray() );
            }
            catch ( SSLToolsException e )
            {
                throw new MojoExecutionException( "Cannot save keystore containing imported certificates: " + e.getMessage(), e );
            }
        }
    }

    private void importAll( Iterable<String> servers, Map<String, SSLToolsException> errors )
    {
        for ( String server : servers )
        {
            String host = server;
            int port = -1;
            
            int idx = server.indexOf( ":" );
            if ( idx > 0 )
            {
                host = server.substring( 0, idx );
                port = Integer.parseInt( server.substring( idx+1 ) );
            }
            
            try
            {
                importer.importServerCertificates( host, port, sourceKeystore, sourceStorepass.toCharArray(), keystore,
                                                   storepass.toCharArray() );
            }
            catch ( SSLToolsException e )
            {
                errors.put( server, e );
            }
        }
    }

}
