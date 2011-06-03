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

import javax.net.ssl.X509TrustManager;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

class SavingTrustManager
    implements X509TrustManager
{

    private final X509TrustManager tm;

    private X509Certificate[] chain;

    SavingTrustManager( final X509TrustManager tm )
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
