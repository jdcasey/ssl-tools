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
