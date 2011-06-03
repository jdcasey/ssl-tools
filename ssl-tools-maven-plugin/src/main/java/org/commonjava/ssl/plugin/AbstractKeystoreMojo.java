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
import org.apache.maven.plugin.logging.Log;

import java.io.File;

abstract class AbstractKeystoreMojo
    implements Mojo
{

    private Log log;

    /**
     * Keystore file into which the client certificate should be imported.
     * 
     * @parameter expression="${import.keystore}" default-value="${java.home}/lib/security/jssecerts"
     */
    protected File keystore;

    /**
     * Password for the Keystore file.
     * 
     * @parameter expression="${import.storepass}" default="changeit"
     */
    protected String storepass;

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