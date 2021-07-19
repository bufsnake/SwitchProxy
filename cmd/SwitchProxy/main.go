package main

import (
	"flag"
	"github.com/bufsnake/SwitchProxy/config"
	"github.com/bufsnake/SwitchProxy/internal"
	"io/ioutil"
	"log"
	"strings"
)

func main() {
	terminal := config.Terminal{}
	flag.StringVar(&terminal.Listen, "listen", "127.0.0.1:8081", "listen port")
	flag.StringVar(&terminal.Proxy, "proxy", "http://127.0.0.1:8080", "proxy address,support http/socks4/socks5 protocol")
	flag.StringVar(&terminal.ProxyList, "proxy-list", "", "proxy address list,support http/socks4/socks5 protocol")
	flag.Parse()
	if terminal.Listen == "" {
		flag.Usage()
		return
	}
	proxys := make(map[string]interface{})
	if terminal.ProxyList != "" {
		file, err := ioutil.ReadFile(terminal.ProxyList)
		if err != nil {
			log.Fatal(err)
		}
		split := strings.Split(string(file), "\n")
		for i := 0; i < len(split); i++ {
			split[i] = strings.Trim(split[i], "\r")
			if len(split[i]) != 0 {
				proxys[split[i]] = nil
			}
		}
	} else if terminal.Proxy != "" {
		proxys[terminal.Proxy] = nil
	} else {
		flag.Usage()
		return
	}
	err := internal.RunSwitchProxy(proxys, terminal)
	if err != nil {
		log.Fatal(err)
	}
}
