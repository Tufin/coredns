package whitelist

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"

	"time"

	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"k8s.io/api/core/v1"
	api "k8s.io/api/core/v1"
)

var log = clog.NewWithPlugin("whitelist")

type kubeAPI interface {
	ServiceList() []*api.Service
	GetNamespaceByName(string) (*api.Namespace, error)
	PodIndex(string) []*api.Pod
}

type whitelist struct {
	Kubernetes         kubeAPI
	Next               plugin.Handler
	Discovery          DiscoveryServiceClient
	FallthroughSources []string
	FallthroughDomains []string
	Configuration      whitelistConfig
	plugin.Zones
}

func (whitelist whitelist) ServeDNS(ctx context.Context, rw dns.ResponseWriter, r *dns.Msg) (int, error) {

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative, m.RecursionAvailable = true, true
	remoteAddr := rw.RemoteAddr()
	state := request.Request{W: rw, Req: r, Context: ctx}

	// resolve IP
	var sourceIPAddr string
	if ip, ok := remoteAddr.(*net.UDPAddr); !ok {
		log.Debug("failed to cast source IP")
		return plugin.NextOrFailure(whitelist.Name(), whitelist.Next, ctx, rw, r)
	} else {
		sourceIPAddr = ip.IP.String()
		if sourceIPAddr == "" {
			log.Debugf("empty source IP: '%+v'", ip)
			return plugin.NextOrFailure(whitelist.Name(), whitelist.Next, ctx, rw, r)
		}
	}
	log.Debugf("source IP: '%s', request: '%s'", sourceIPAddr, state.Name())

	// fallthrough sources
	for _, currSource := range whitelist.FallthroughSources {
		if strings.EqualFold(currSource, sourceIPAddr) {
			log.Debugf("fallthrough source IP: '%s' (request: '%s')", sourceIPAddr, state.Name())
			return plugin.NextOrFailure(whitelist.Name(), whitelist.Next, ctx, rw, r)
		}
	}

	segs := dns.SplitDomainName(state.Name())
	if len(segs) <= 1 {
		log.Debugf("number of segments: '%d' for state name: '%s'", len(segs), state.Name())
		return plugin.NextOrFailure(whitelist.Name(), whitelist.Next, ctx, rw, r)
	}

	// convert source IP to service
	sourceService := whitelist.getServiceFromIP(sourceIPAddr)
	if sourceService == nil {
		log.Debugf("failed to convert source IP: '%s' to service (request: '%s')", sourceIPAddr, state.Name())
		return plugin.NextOrFailure(whitelist.Name(), whitelist.Next, ctx, rw, r)
	}
	log.Debugf("source IP: '%s', service: '%+v', request: '%s'", sourceIPAddr, sourceService, state.Name())

	// fallthrough request
	query := strings.TrimRight(state.Name(), ".")
	for _, domain := range whitelist.FallthroughDomains {
		if strings.EqualFold(domain, query) {
			log.Debugf("fallthrough request: '%s' (source IP: '%s')", query, sourceIPAddr)
			return plugin.NextOrFailure(whitelist.Name(), whitelist.Next, ctx, rw, r)
		}
	}

	if sourceService == nil || sourceService.Name == "" {
		log.Debugf("Service not found (source IP: '%s', request: '%s')", sourceIPAddr, state.Name())
		return plugin.NextOrFailure(whitelist.Name(), whitelist.Next, ctx, rw, r)
	}

	querySrcService := fmt.Sprintf("%s.%s", sourceService.Name, sourceService.Namespace)
	queryDstLocation, origin, dstConf := "", "", ""

	if ns, err := whitelist.Kubernetes.GetNamespaceByName(segs[1]); err != nil {
		log.Debugf("Assuming '%s' is an egress ('%v')", segs[1], err)
		//make sure that this is real external query without .cluster.local in the end
		zone := plugin.Zones(whitelist.Zones).Matches(state.Name())
		if zone != "" {
			return plugin.NextOrFailure(whitelist.Name(), whitelist.Next, ctx, rw, r)
		}
		//external query
		origin = "dns"
		queryDstLocation = state.Name()
		dstConf = strings.TrimRight(state.Name(), ".")
	} else {
		//local kubernetes dstConf
		log.Debugf("namespace '%s', assuming local kubernetes query", ns)
		queryDstLocation = fmt.Sprintf("%s.listentry.%s", segs[0], segs[1])
		origin = ""
		dstConf = fmt.Sprintf("%s.%s", segs[0], segs[1])
	}

	serviceName := fmt.Sprintf("%s.svc.%s", querySrcService, whitelist.Zones[0])

	// update kite
	if whitelist.Configuration.blacklist {
		go whitelist.log(serviceName, queryDstLocation, origin, "allow")
		return plugin.NextOrFailure(whitelist.Name(), whitelist.Next, ctx, rw, r)
	}
	if whitelisted, ok := whitelist.Configuration.SourceToDestination[querySrcService]; ok {
		if _, ok := whitelisted[dstConf]; ok {
			go whitelist.log(serviceName, queryDstLocation, origin, "allow")
			return plugin.NextOrFailure(whitelist.Name(), whitelist.Next, ctx, rw, r)
		}
	}

	go whitelist.log(serviceName, queryDstLocation, origin, "deny")

	m.SetRcode(r, dns.RcodeNameError)
	if err := rw.WriteMsg(m); err != nil {
		log.Errorf("failed to write a reply back to the client with '%v'", err)
	}

	return dns.RcodeNameError, errors.New("not whitelisted")
}

func (whitelist whitelist) getServiceFromIP(ipAddr string) *v1.Service {

	services := whitelist.Kubernetes.ServiceList()
	if services == nil || len(services) == 0 {
		log.Debugf("Trying to convert IP '%s' into service, but no services found", ipAddr)
		return nil
	}

	var pod *api.Pod
	if err := RetryWithTimeout(1*time.Millisecond, 30*time.Microsecond, func() bool {

		indexPods := whitelist.Kubernetes.PodIndex(ipAddr)
		if len(indexPods) > 0 {
			pod = indexPods[0]
			return true
		}

		return false
	}); err != nil {
		log.Debugf("failed to translate IP: '%s' into pod with '%v'. indexed: '%+v'",
			ipAddr, err, whitelist.Kubernetes.PodIndex(ipAddr))
		return nil
	}
	log.Debugf("IP translated into pod. IP: '%s', '%+v'", ipAddr, pod)

	var service *v1.Service
	for _, currService := range services {
		for podLabelKey, podLabelValue := range pod.Labels {
			if svcLabelValue, ok := currService.Spec.Selector[podLabelKey]; ok {
				if strings.EqualFold(podLabelValue, svcLabelValue) {
					service = currService
				}
			}
		}
	}

	return service
}

func (whitelist whitelist) getIPByServiceName(serviceName string) string {

	if serviceName == "" {
		return ""
	}

	serviceNameParts := strings.Split(serviceName, ".")

	service, namespace := "", ""

	//only service name introduced ("zipkin")"
	if len(serviceNameParts) == 1 {
		service, namespace = serviceName, v1.NamespaceDefault
	}

	if len(serviceNameParts) == 2 {
		service, namespace = serviceNameParts[0], serviceNameParts[1]
	} else {
		return ""
	}

	services := whitelist.Kubernetes.ServiceList()
	if services == nil || len(services) == 0 {
		return ""
	}

	for _, svc := range services {
		if svc.Name == service && svc.Namespace == namespace {
			return svc.Spec.ClusterIP
		}
	}

	return ""
}

func (whitelist whitelist) Name() string {
	return "whitelist"
}

func (whitelist whitelist) log(service string, query, origin, action string) {

	fields := make(map[string]string)
	fields["src"] = service
	fields["dst"] = strings.TrimRight(query, ".")
	fields["action"] = action
	fields["origin"] = origin

	actionBytes := new(bytes.Buffer)
	if err := json.NewEncoder(actionBytes).Encode(fields); err != nil {
		log.Errorf("failed to encode log data with '%v'", err)
		return
	}

	if _, err := whitelist.Discovery.Discover(context.Background(), &Discovery{Msg: actionBytes.Bytes()}); err != nil {
		log.Errorf("log not sent to discovery: '%v'", err)
	}
}
