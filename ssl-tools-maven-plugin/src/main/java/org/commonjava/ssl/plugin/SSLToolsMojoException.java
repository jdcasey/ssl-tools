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

import org.apache.maven.plugin.MojoExecutionException;
import org.commonjava.ssl.SSLToolsException;

import java.io.PrintStream;
import java.io.PrintWriter;
import java.util.Map;

public class SSLToolsMojoException
    extends MojoExecutionException
{
    
    private static final long serialVersionUID = 1L;
    private final Map<String, SSLToolsException> errors;

    public SSLToolsMojoException( Map<String, SSLToolsException> errors )
    {
        super( ( errors== null || errors.isEmpty() ? "UNKNOWN" : "" + errors.size() ) + " errors encountered while importing certificates." );
        this.errors = errors;
    }

    @Override
    public void printStackTrace()
    {
        printStackTrace( System.err );
    }

    @Override
    public void printStackTrace( PrintStream out )
    {
        out.println( getMessage() );
        out.println();
        if ( errors != null && !errors.isEmpty() )
        {
            for ( Map.Entry<String, SSLToolsException> entry : errors.entrySet() )
            {
                out.append( entry.getKey() ).append( ": " ).println();
                entry.getValue().printStackTrace( out );
                out.println();
            }
            out.println();
        }
    }

    @Override
    public void printStackTrace( PrintWriter out )
    {
        out.println( getMessage() );
        out.println();
        if ( errors != null && !errors.isEmpty() )
        {
            for ( Map.Entry<String, SSLToolsException> entry : errors.entrySet() )
            {
                out.append( entry.getKey() ).append( ": " ).println();
                entry.getValue().printStackTrace( out );
                out.println();
            }
            out.println();
        }
    }

    public static CharSequence formatSummary( Map<String, SSLToolsException> errors )
    {
        if ( errors == null || errors.isEmpty() )
        {
            return "0 errors reported.";
        }
        
        StringBuilder sb = new StringBuilder();
        
        sb.append( errors.size() ).append( " errors encountered while importing certificates:" );
        for ( Map.Entry<String, SSLToolsException> entry : errors.entrySet() )
        {
            sb.append( "\n  " ).append( entry.getKey() ).append( ": " ).append( entry.getValue().getMessage() );
        }
        sb.append( "\n\nPlease re-run with -e to print stack traces.\n" );
        
        return sb;
    }

}
