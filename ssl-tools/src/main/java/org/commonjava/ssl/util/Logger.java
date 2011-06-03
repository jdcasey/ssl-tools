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

package org.commonjava.ssl.util;

import org.slf4j.LoggerFactory;

import java.text.MessageFormat;
import java.util.IllegalFormatException;

public final class Logger
{
    
    private final org.slf4j.Logger logger;
    
    public Logger( Class<?> clazz )
    {
        logger = LoggerFactory.getLogger( clazz );
    }
    
    public Logger( String name )
    {
        logger = LoggerFactory.getLogger( name );
    }
    
    public Logger( org.slf4j.Logger logger )
    {
        this.logger = logger;
    }
    
    public org.slf4j.Logger getLogger()
    {
        return logger;
    }
    
    public Logger debug( String format, Object...params )
    {
        if ( logger.isDebugEnabled() )
        {
            logger.debug( format( format, params ) );
        }
        
        return this;
    }

    public Logger debug( String format, Throwable error, Object...params )
    {
        if ( logger.isDebugEnabled() )
        {
            logger.debug( format( format, params ), error );
        }
        
        return this;
    }

    public Logger error( String format, Object...params )
    {
        if ( logger.isErrorEnabled() )
        {
            logger.error( format( format, params ) );
        }
        
        return this;
    }

    public Logger error( String format, Throwable error, Object...params )
    {
        if ( logger.isErrorEnabled() )
        {
            logger.error( format( format, params ), error );
        }
        
        return this;
    }

    public Logger info( String format, Object...params )
    {
        if ( logger.isInfoEnabled() )
        {
            logger.info( format( format, params ) );
        }
        
        return this;
    }

    public Logger info( String format, Throwable error, Object...params )
    {
        if ( logger.isInfoEnabled() )
        {
            logger.info( format( format, params ), error );
        }
        
        return this;
    }

    public Logger trace( String format, Object...params )
    {
        if ( logger.isTraceEnabled() )
        {
            logger.trace( format( format, params ) );
        }
        
        return this;
    }

    public Logger trace( String format, Throwable error, Object...params )
    {
        if ( logger.isTraceEnabled() )
        {
            logger.trace( format( format, params ), error );
        }
        
        return this;
    }

    public Logger warn( String format, Object...params )
    {
        if ( logger.isWarnEnabled() )
        {
            logger.warn( format( format, params ) );
        }
        
        return this;
    }

    public Logger warn( String format, Throwable error, Object...params )
    {
        if ( logger.isWarnEnabled() )
        {
            logger.warn( format( format, params ), error );
        }
        
        return this;
    }

    private String format( String format, Object[] params )
    {
        String out = format;
        if ( params == null || params.length < 1 )
        {
            return out;
        }
        
        try
        {
            out = String.format( out, params );
        }
        catch ( IllegalFormatException e )
        {
            try
            {
                out = MessageFormat.format( out, params );
            }
            catch ( IllegalArgumentException e1 )
            {
                out = format;
            }
        }
        
        return out;
    }

}
