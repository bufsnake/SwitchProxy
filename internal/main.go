package internal

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/bufsnake/SwitchProxy/config"
	"github.com/google/martian"
	"github.com/google/martian/mitm"
	"io/ioutil"
	"log"
	"math/big"
	rand2 "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"
)

func RunSwitchProxy(proxys map[string]interface{}, conf config.Terminal) error {
	martian.Init()
	p := martian.NewProxy()
	defer p.Close()
	l, err := net.Listen("tcp", conf.Listen)
	if err != nil {
		return err
	}
	log.Println("listen", l.Addr().String())
	tr := &http.Transport{
		Dial: (&net.Dialer{
			Timeout:   60 * time.Second,
			KeepAlive: 60 * time.Second,
		}).Dial,
		TLSHandshakeTimeout:   60 * time.Second,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	p.SetRoundTripper(tr)

	var x509c *x509.Certificate
	var priv interface{}
	var raw []byte
	_, err = ioutil.ReadFile("./ca.crt")
	if err != nil && strings.HasSuffix(err.Error(), "no such file or directory") {
		x509c, priv, raw, err = newAuthority("House", "localhost", 365*24*time.Hour)
		if err != nil {
			return err
		}
		certOut, _ := os.Create("./ca.crt")
		err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: raw})
		err = certOut.Close()
		priv_ := &rsa.PrivateKey{}
		switch priv.(type) {
		case *rsa.PrivateKey:
			priv_ = priv.(*rsa.PrivateKey)
		}
		keyOut, _ := os.Create("./ca.key")
		err = pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv_)})
		err = keyOut.Close()
		log.Println("please install ca.crt")
	} else {
		tlsc, err := tls.LoadX509KeyPair("./ca.crt", "./ca.key")
		if err != nil {
			return err
		}
		priv = tlsc.PrivateKey
		x509c, err = x509.ParseCertificate(tlsc.Certificate[0])
		if err != nil {
			return err
		}
	}
	var mitm_config *mitm.Config
	mitm_config, err = mitm.NewConfig(x509c, priv)
	if err != nil {
		return err
	}
	mitm_config.SkipTLSVerify(false)
	p.SetMITM(mitm_config)

	rand2.Seed(time.Now().Unix())
	proxys_ := make([]string, 0)
	for proxy, _ := range proxys {
		proxys_ = append(proxys_, proxy)
	}
	m := modify{proxys: proxys_, martian: &p}
	p.SetRequestModifier(&m)

	go func() {
		err = p.Serve(l)
		if err != nil {
			log.Fatal(err)
			return
		}
	}()

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt)
	<-sigc
	log.Fatal("martian: shutting down")
	return nil
}

type modify struct {
	proxys  []string
	martian **martian.Proxy
}

func (v *modify) ModifyRequest(req *http.Request) error {
	url_proxy, err := url.Parse(v.proxys[rand2.Intn(len(v.proxys))])
	if err != nil {
		log.Println("request", req.URL, "proxy error", err)
		return err
	}
	log.Println("request", req.URL, "via proxy", url_proxy)
	(*v.martian).SetDownstreamProxy(url_proxy)
	return nil
}

func newAuthority(name, organization string, validity time.Duration) (x509c *x509.Certificate, priv *rsa.PrivateKey, raw []byte, err error) {
	priv, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}
	pub := priv.Public()

	// Subject Key Identifier support for end entity certificate.
	// https://www.ietf.org/rfc/rfc3280.txt (section 4.2.1.2)
	pkixpub, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, nil, err
	}
	h := sha1.New()
	h.Write(pkixpub)
	keyID := h.Sum(nil)

	// TODO: keep a map of used serial numbers to avoid potentially reusing a
	// serial multiple times.
	serial, err := rand.Int(rand.Reader, big.NewInt(0).SetBytes(bytes.Repeat([]byte{255}, 20)))
	if err != nil {
		return nil, nil, nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   name,
			Organization: []string{organization},
		},
		SubjectKeyId:          keyID,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		NotBefore:             time.Now().Add(-validity),
		NotAfter:              time.Now().Add(validity),
		DNSNames:              []string{name},
		IsCA:                  true,
	}

	raw, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, nil, nil, err
	}

	x509c, err = x509.ParseCertificate(raw)
	if err != nil {
		return nil, nil, nil, err
	}

	return x509c, priv, raw, nil
}
