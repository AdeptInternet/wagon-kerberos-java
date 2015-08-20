package org.adeptnet.maven.wagon.providers.http;

/*
 * ====================================================================
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 */
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.naming.NamingException;
import org.apache.http.annotation.Immutable;
import org.apache.http.auth.AuthScheme;
import org.apache.http.auth.AuthSchemeFactory;
import org.apache.http.auth.AuthSchemeProvider;
import org.apache.http.impl.auth.SPNegoScheme;
import org.apache.http.params.HttpParams;
import org.apache.http.protocol.HttpContext;
import org.ietf.jgss.GSSException;

/**
 * {@link AuthSchemeProvider} implementation that creates and initializes
 * {@link SPNegoScheme} instances.
 *
 * @since 4.2
 */
@Immutable
@SuppressWarnings("deprecation")
public class SPNegoSchemeFactory implements AuthSchemeFactory, AuthSchemeProvider {

    private static final Logger LOG = Logger.getLogger(SPNegoSchemeFactory.class.getName());

    private final boolean stripPort;

    public SPNegoSchemeFactory(final boolean stripPort) {
        super();
        this.stripPort = stripPort;
    }

    public SPNegoSchemeFactory() {
        this(false);
    }

    public boolean isStripPort() {
        return stripPort;
    }

    @Override
    public AuthScheme newInstance(final HttpParams params) {
        return new InternalSPNegoScheme(this.stripPort);
    }

    @Override
    public AuthScheme create(final HttpContext context) {
        return new InternalSPNegoScheme(this.stripPort);
    }

    private static class InternalCacheEntry {

        private static final long CACHE = 60 * 1000;

        private final String server;
        private final long age;
        private final byte[] token;

        public InternalCacheEntry(String server, long age, byte[] token) {
            this.server = server;
            this.age = age;
            this.token = token;
        }

        public String getServer() {
            return server;
        }

        public long getAge() {
            return age;
        }

        public byte[] getToken() {
            return token;
        }

        public boolean hasExpired() {
            return age + CACHE < System.currentTimeMillis();
        }
    }

    private static class InternalSPNegoScheme extends SPNegoScheme {

        private static final java.util.Map<String, InternalCacheEntry> cache = new java.util.HashMap<>();

        public InternalSPNegoScheme(boolean stripPort) {
            super(stripPort);
        }

        public InternalSPNegoScheme() {
            this(false);
        }

        private String normalize(final String data) {
            if (data.isEmpty()) {
                return data;
            }
            if (data.endsWith(".")) {
                return normalize(data.substring(0, data.length() - 1));
            }
            return data;
        }

        private String recurseResolveToA(final Nameserver ns, final Set<String> checked, final String host) throws NamingException {
            if (checked.contains(host)) {
                throw new NamingException(String.format("Recursive Name Lookup: %s", checked));
            }
            final String[] clookup = ns.lookup(host, "cname");
            if (clookup.length != 0) {
                checked.add(host);
                return recurseResolveToA(ns, checked, normalize(clookup[0]));
            }

            return host;
        }

        @Override
        protected byte[] generateToken(byte[] input, String authServer) throws GSSException {
            if (cache.containsKey(authServer)) {
                final InternalCacheEntry entry = cache.get(authServer);
                if (entry.hasExpired()) {
                    cache.remove(authServer);
                }
            }
            if (!cache.containsKey(authServer)) {
                String server;
                try {
                    //Resolving to final A record, otherwise Kerberos fails with Server Not Found
                    server = recurseResolveToA(new Nameserver(), new HashSet<>(), authServer);
                } catch (NamingException ex) {
                    LOG.log(Level.SEVERE, null, ex);
                    server = authServer;
                }
                final InternalCacheEntry entry = new InternalCacheEntry(authServer, System.currentTimeMillis(), super.generateToken(input, server));
                cache.put(authServer, entry);
            }
            return cache.get(authServer).getToken();
        }
    }
}
