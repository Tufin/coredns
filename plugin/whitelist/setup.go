package whitelist

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/kubernetes"
	"github.com/mholt/caddy"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

type dnsConfig struct {
	Blacklist           bool                `json:"blacklist"`
	ServicesToWhitelist map[string][]string `json:"services"`
}

type whitelistConfig struct {
	blacklist           bool
	SourceToDestination map[string]map[string]struct{}
}

func init() {

	caddy.RegisterPlugin("whitelist", caddy.Plugin{
		ServerType: "dns",
		Action:     setup,
	})
}

func kubernetesParse(c *caddy.Controller) (*kubernetes.Kubernetes, error) {

	var (
		k8s *kubernetes.Kubernetes
		err error
	)

	i := 0
	for c.Next() {
		if i > 0 {
			return nil, plugin.ErrOnce
		}
		i++

		k8s, err = kubernetes.ParseStanza(c)
		if err != nil {
			return k8s, err
		}
	}

	return k8s, nil
}

func setup(c *caddy.Controller) error {

	whitelist := &whitelist{
		Configuration: whitelistConfig{blacklist: true},
	}

	k8s, err := kubernetesParse(c)
	if err != nil {
		return plugin.Error("whitelist", err)
	}

	if len(k8s.Zones) != 1 {
		return errors.New("whitelist zones length should be 1 (cluster zone only)")
	}

	err = k8s.InitKubeCache()
	if err != nil {
		return err
	}

	k8s.RegisterKubeCache(c)
	whitelist.Kubernetes = k8s.APIConn
	whitelist.Zones = k8s.Zones
	whitelist.InitDiscoveryServer(c)

	if sources := os.Getenv("TUFIN_FALLTHROUGH_SOURCES"); sources != "" {
		whitelist.FallthroughSources = strings.Split(sources, ",")
	}
	if domains := os.Getenv("TUFIN_FALLTHROUGH_DOMAINS"); domains != "" {
		whitelist.FallthroughDomains = strings.Split(domains, ",")
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		whitelist.Next = next
		return whitelist
	})

	return nil
}

func (whitelist *whitelist) InitDiscoveryServer(c *caddy.Controller) {

	c.OnStartup(func() error {

		const env = "TUFIN_GRPC_DISCOVERY_URL"
		if discoveryURL := GetEnv(env); discoveryURL != "" {
			discoveryURL, err := url.Parse(discoveryURL)
			if err != nil {
				log.Warningf("can not parse discovery URL: '%s' with '%v'", err)
			} else {
				ip := whitelist.getIPByServiceName(discoveryURL.Scheme)
				log.Infof("Discovery URL: '%s', IP: '%s'", discoveryURL, ip)
				if dc, conn := newDiscoveryClient(fmt.Sprintf("%s:%s", ip, discoveryURL.Opaque)); dc != nil && conn != nil {
					whitelist.Discovery = dc
					go whitelist.config()
					c.OnShutdown(func() error {
						return conn.Close()
					})
				}
			}
		} else {
			log.Infof("Empty environment variable: '%s'", env)
		}

		return nil
	})
}

func newDiscoveryClient(discoveryURL string) (DiscoveryServiceClient, *grpc.ClientConn) {

	cc, err := grpc.Dial(discoveryURL, grpc.WithInsecure(),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 10 * time.Minute, Timeout: 30 * time.Second, PermitWithoutStream: true}))
	if err != nil {
		log.Errorf("failed to create gRPC connection with '%v'", err)
		return nil, nil
	}

	return NewDiscoveryServiceClient(cc), cc
}

func (whitelist *whitelist) config() {

	for {
		configuration, err := whitelist.Discovery.Configure(context.Background(), &ConfigurationRequest{})
		if err != nil {
			log.Errorf("failed to stream whitelist discovery configure with '%v' retrying...", err)
			sleep()
			continue
		}
		for {
			resp, err := configuration.Recv()
			if err == io.EOF {
				log.Errorf("failed to receive stream whitelist discovery configuration with '%v' (io.EOF) retrying...", err)
				sleep()
				break
			}

			if err != nil {
				log.Errorf("failed to receive stream whitelist discovery configuration with '%v' retrying...", err)
				sleep()
				break
			}

			var dnsConfiguration dnsConfig
			if err = json.Unmarshal(resp.GetMsg(), &dnsConfiguration); err != nil {
				log.Errorf("failed to unmarshal configuration stream message '%v' with '%v' retrying...", resp.GetMsg(), err)
				sleep()
				continue
			}

			whitelist.Configuration = whitelistConfig{blacklist: dnsConfiguration.Blacklist, SourceToDestination: convert(dnsConfiguration.ServicesToWhitelist)}
			log.Infof("DNS Configuration: '%+v'", whitelist.Configuration)
		}
	}
}

func convert(conf map[string][]string) map[string]map[string]struct{} {

	ret := make(map[string]map[string]struct{})
	for k, v := range conf {
		ret[k] = make(map[string]struct{})
		for _, item := range v {
			ret[k][item] = struct{}{}
		}
	}

	return ret
}

func sleep() {

	d := time.Duration(rand.Int31n(15)+5) * time.Second
	log.Debugf("Going to sleep '%v'", d)
	time.Sleep(d)
}
