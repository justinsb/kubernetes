/*
Copyright 2015 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"github.com/golang/glog"
	"golang.org/x/net/proxy"

	utilnet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/apimachinery/third_party/forked/golang/netutil"
)

type dialFuncToProxyDialer struct {
	dialFunc utilnet.DialFunc
}

func (d *dialFuncToProxyDialer) Dial(network, addr string) (net.Conn, error) {
	ctx := context.TODO()
	return d.dialFunc(ctx, network, addr)
}

//type DialFunc func(ctx context.Context, net, addr string) (net.Conn, error)

func addProxyToDialer(dialer utilnet.DialFunc, proxyURL *url.URL) (utilnet.DialFunc, error) {
	if proxyURL == nil {
		return dialer, nil
	}
	proxyDialer := &dialFuncToProxyDialer{dialFunc: dialer}
	proxied, err := proxy.FromURL(proxyURL, proxyDialer)
	if err != nil {
		return nil, fmt.Errorf("error building proxied dialer: %v", err)
	}
	return func(ctx context.Context, network string, addr string) (net.Conn, error) {
		return proxied.Dial(network, addr)
	}, nil
}

func DialURL(ctx context.Context, req *http.Request, transport http.RoundTripper) (net.Conn, error) {
	reqURL := req.URL
	glog.Infof("DialURL url=%+v transport=%+v", reqURL, transport)

	dialAddr := netutil.CanonicalAddr(reqURL)

	dialer, err := utilnet.DialerFor(transport)
	if err != nil {
		glog.Infof("Unable to unwrap transport %T to get dialer: %v", transport, err)
	}

	var proxyURL *url.URL
	switch transport := transport.(type) {
	case *http.Transport:
		if transport.Proxy == nil {
			glog.Infof("is http.Transport but proxy is nil")
		} else {
			p, err := transport.Proxy(req)
			if err != nil {
				return nil, fmt.Errorf("error getting proxy for request: %v", err)
			}
			proxyURL = p
		}
	default:
		glog.Infof("unexpected transport type %T %v", transport, transport)
	}

	if proxyURL != nil {
		glog.Infof("using ProxyURL=%+v", *proxyURL)
	}

	switch reqURL.Scheme {
	case "http":
		if dialer == nil {
			var d net.Dialer
			dialer = d.DialContext
		}

		dialer, err = addProxyToDialer(dialer, proxyURL)
		if err != nil {
			return nil, err
		}

		return dialer(ctx, "tcp", dialAddr)
	case "https":
		// Get the tls config from the transport if we recognize it
		var tlsConfig *tls.Config
		var tlsConn *tls.Conn
		var err error
		tlsConfig, err = utilnet.TLSClientConfig(transport)
		if err != nil {
			glog.V(5).Infof("Unable to unwrap transport %T to get at TLS config: %v", transport, err)
		}

		if dialer == nil {
			var d net.Dialer
			dialer = d.DialContext
		}

		if dialer != nil {
			dialer, err = addProxyToDialer(dialer, proxyURL)
			if err != nil {
				return nil, err
			}

			// We have a dialer; use it to open the connection, then
			// create a tls client using the connection.
			netConn, err := dialer(ctx, "tcp", dialAddr)
			if err != nil {
				return nil, err
			}
			if tlsConfig == nil {
				// tls.Client requires non-nil config
				glog.Warningf("using custom dialer with no TLSClientConfig. Defaulting to InsecureSkipVerify")
				// tls.Handshake() requires ServerName or InsecureSkipVerify
				tlsConfig = &tls.Config{
					InsecureSkipVerify: true,
				}
			} else if len(tlsConfig.ServerName) == 0 && !tlsConfig.InsecureSkipVerify {
				// tls.Handshake() requires ServerName or InsecureSkipVerify
				// infer the ServerName from the hostname we're connecting to.
				inferredHost := dialAddr
				if host, _, err := net.SplitHostPort(dialAddr); err == nil {
					inferredHost = host
				}
				// Make a copy to avoid polluting the provided config
				tlsConfigCopy := tlsConfig.Clone()
				tlsConfigCopy.ServerName = inferredHost
				tlsConfig = tlsConfigCopy
			}
			tlsConn = tls.Client(netConn, tlsConfig)
			if err := tlsConn.Handshake(); err != nil {
				netConn.Close()
				return nil, err
			}

		} else {
			// Dial. This Dial method does not allow to pass a context unfortunately
			tlsConn, err = tls.Dial("tcp", dialAddr, tlsConfig)
			if err != nil {
				return nil, err
			}
		}

		// Return if we were configured to skip validation
		if tlsConfig != nil && tlsConfig.InsecureSkipVerify {
			return tlsConn, nil
		}

		// Verify
		host, _, _ := net.SplitHostPort(dialAddr)
		if tlsConfig != nil && len(tlsConfig.ServerName) > 0 {
			host = tlsConfig.ServerName
		}
		if err := tlsConn.VerifyHostname(host); err != nil {
			tlsConn.Close()
			return nil, err
		}

		return tlsConn, nil
	default:
		return nil, fmt.Errorf("Unknown scheme: %s", reqURL.Scheme)
	}
}
