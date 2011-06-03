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

import javax.net.ssl.X509TrustManager;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class SavingTrustManager
    implements X509TrustManager
{

    private final X509TrustManager tm;

    private X509Certificate[] chain;

    public SavingTrustManager( final X509TrustManager tm )
    {
        this.tm = tm;
    }

    public X509Certificate[] getAcceptedIssuers()
    {
        throw new UnsupportedOperationException();
    }

    public void checkClientTrusted( final X509Certificate[] chain, final String authType )
        throws CertificateException
    {
        throw new UnsupportedOperationException();
    }

    public void checkServerTrusted( final X509Certificate[] chain, final String authType )
        throws CertificateException
    {
        this.chain = chain;
        tm.checkServerTrusted( chain, authType );
    }

    public X509Certificate[] getChain()
    {
        return chain;
    }
}
