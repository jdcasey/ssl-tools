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

import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Level;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.apache.log4j.SimpleLayout;
import org.apache.log4j.spi.Configurator;
import org.apache.log4j.spi.LoggerRepository;
import org.apache.maven.plugin.Mojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugin.logging.Log;

import java.io.File;
import java.net.URL;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

abstract class AbstractSSLToolsMojo
    implements Mojo
{
    
    private static final Map<String, Level> LOG4J_LEVELS = new HashMap<String, Level>()
    {
        private static final long serialVersionUID = 1L;

        {
            put( "trace", Level.TRACE );
            put( "debug", Level.DEBUG );
            put( "info", Level.INFO );
            put( "warn", Level.WARN );
            put( "error", Level.ERROR );
        }
    };

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
     * @parameter expression="${import.storepass}" default-value="changeit"
     */
    protected String storepass;

    /**
     * If <code>true</code>, throw an exception to stop the build if there are import failures. (Otherwise, simply
     * report the failures and continue.)
     * 
     * @parameter expression="${import.stop-on-failure}" default-value="false"
     */
    protected boolean stopOnFailure;
    
    /**
     * Set the log-level for ssl-tools classes. Examples: trace, debug, info, warn
     * 
     * @parameter expression="${import.log}"
     */
    protected String logLevel;

    public File getKeystore()
    {
        return keystore;
    }

    public void setKeystore( File keystore )
    {
        this.keystore = keystore;
    }

    public String getStorepass()
    {
        return storepass;
    }

    public void setStorepass( String storepass )
    {
        this.storepass = storepass;
    }

    public boolean isStopOnFailure()
    {
        return stopOnFailure;
    }

    public void setStopOnFailure( boolean stopOnFailure )
    {
        this.stopOnFailure = stopOnFailure;
    }

    public Log getLog()
    {
        return log;
    }

    public void setLog( final Log log )
    {
        this.log = log;
    }

    private Level getLog4jLevel()
    {
        if ( logLevel != null )
        {
            return LOG4J_LEVELS.get( logLevel.toLowerCase().trim() );
        }
        
        return log.isDebugEnabled() ? Level.DEBUG : Level.INFO;
    }

    public void execute()
        throws MojoExecutionException, MojoFailureException
    {
        final Level level = getLog4jLevel();
        
        final Configurator log4jConfigurator = new Configurator()
        {
//            @SuppressWarnings( "unchecked" )
            public void doConfigure( final URL notUsed, final LoggerRepository repo )
            {
                
                ConsoleAppender cAppender = new ConsoleAppender( new SimpleLayout() );
                cAppender.setThreshold( level );

//                repo.setThreshold( level );
//                repo.getRootLogger().removeAllAppenders();
//                repo.getRootLogger().addAppender( cAppender );
                
                Logger logger = repo.getLogger( "org.commonjava" );
                logger.setLevel( level );
                logger.removeAllAppenders();
                logger.addAppender( cAppender );

//                final Enumeration<Logger> loggers = repo.getCurrentLoggers();
//                while ( loggers.hasMoreElements() )
//                {
//                    final Logger logger = loggers.nextElement();
////                    logger.setLevel( level );
//                    logger.removeAllAppenders();
//                    logger.addAppender( cAppender );
//                    logger.setLevel( level );
//                }
            }
        };

        log4jConfigurator.doConfigure( null, LogManager.getLoggerRepository() );
        
        doExecute();
    }

    protected abstract void doExecute()
        throws MojoExecutionException, MojoFailureException;

}
