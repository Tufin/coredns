package whitelist

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	api "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type mockHandler struct {
	Served bool
}

type mockDiscovery struct {
	discovered [][]byte
	logged     chan bool
}

type mockKubeAPI struct{}

func newMockHandler() *mockHandler { return &mockHandler{Served: false} }

func (mh *mockHandler) ServeDNS(context.Context, dns.ResponseWriter, *dns.Msg) (int, error) {

	mh.Served = true

	return 1, nil
}

func (mh mockHandler) Name() string {

	return "mockHandler"
}

func (mc *mockDiscovery) Discover(ctx context.Context, in *Discovery, opts ...grpc.CallOption) (*DiscoveryResponse, error) {

	mc.discovered = append(mc.discovered, in.Msg)
	mc.logged <- true

	return &DiscoveryResponse{}, nil
}

func (mc mockDiscovery) Configure(ctx context.Context, in *ConfigurationRequest, opts ...grpc.CallOption) (DiscoveryService_ConfigureClient, error) {

	return nil, nil
}

func (mk mockKubeAPI) ServiceList() []*api.Service {

	return []*api.Service{
		{
			ObjectMeta: meta.ObjectMeta{
				Name:      "svc1",
				Namespace: "testns",
			},
			Spec: api.ServiceSpec{
				ClusterIP: "10.0.0.1",
				Selector:  map[string]string{"app": "test"},
				Ports: []api.ServicePort{{
					Name:     "http",
					Protocol: "tcp",
					Port:     80,
				}},
			},
		},
		{
			ObjectMeta: meta.ObjectMeta{
				Name:      "hdls1",
				Namespace: "testns",
			},
			Spec: api.ServiceSpec{
				ClusterIP: api.ClusterIPNone,
				Selector:  map[string]string{"app": "test2"},
			},
		},
		{
			ObjectMeta: meta.ObjectMeta{
				Name:      "external",
				Namespace: "testns",
			},
			Spec: api.ServiceSpec{
				ExternalName: "coredns.io",
				Ports: []api.ServicePort{{
					Name:     "http",
					Protocol: "tcp",
					Port:     80,
				}},
				Type: api.ServiceTypeExternalName,
			},
		},
	}
}

func (mk mockKubeAPI) GetNamespaceByName(name string) (*api.Namespace, error) {

	if name == "testns" {
		return &api.Namespace{
			ObjectMeta: meta.ObjectMeta{
				Name: name,
			},
		}, nil
	}

	return nil, errors.New("no namespace")
}

func (mk mockKubeAPI) PodIndex(string) []*api.Pod {

	return []*api.Pod{{
		ObjectMeta: meta.ObjectMeta{
			Namespace: "podns",
			Labels:    map[string]string{"app": "test"},
		},
		Status: api.PodStatus{
			PodIP: "10.240.0.1", // Remote IP set in test.ResponseWriter
		},
	}}
}

func TestWhitelist_ServeDNS_NotWhitelisted(t *testing.T) {

	next := newMockHandler()
	whitelistPlugin := whitelist{Kubernetes: &mockKubeAPI{}, Next: next,
		Discovery:     &mockDiscovery{logged: make(chan bool, 1)},
		Zones:         []string{"cluster.local"},
		Configuration: whitelistConfig{blacklist: false}}

	rw := &test.ResponseWriter{}
	req := new(dns.Msg)

	req.SetQuestion("www.google.com.", dns.TypeA)

	whitelistPlugin.ServeDNS(context.Background(), rw, req)

	assert.False(t, next.Served)
}

func TestWhitelist_ServeDNS_ConfiguredNotWhitelisted(t *testing.T) {

	next := newMockHandler()

	const src, srcNamespace = "svc1", "testns"
	whitelistPlugin := whitelist{Kubernetes: &mockKubeAPI{}, Next: next,
		Discovery: &mockDiscovery{logged: make(chan bool, 1)},
		Zones:     []string{"cluster.local"},
		Configuration: whitelistConfig{blacklist: false, SourceToDestination: toStrictPolicy([]*PolicyRule{
			{Source: &Resource{Name: src, Namespace: srcNamespace}, Destination: &Resource{Name: "www.google.com", Type: ResourceType_DNS}},
			{Source: &Resource{Name: src, Namespace: srcNamespace}, Destination: &Resource{Name: "www.amazon.com", Type: ResourceType_DNS}},
		})}}

	rw := &test.ResponseWriter{}
	req := new(dns.Msg)

	req.SetQuestion("www.google2.com.", dns.TypeA)

	whitelistPlugin.ServeDNS(context.Background(), rw, req)

	assert.False(t, next.Served)
}

func TestWhitelist_ServeDNS_Whitelisted(t *testing.T) {

	next := newMockHandler()

	const src, srcNamespace = "svc1", "testns"
	whitelistPlugin := whitelist{Kubernetes: &mockKubeAPI{}, Next: next,
		Discovery: &mockDiscovery{logged: make(chan bool, 1)},
		Zones:     []string{"cluster.local"},
		Configuration: whitelistConfig{blacklist: true, SourceToDestination: toStrictPolicy([]*PolicyRule{
			{Source: &Resource{Name: src, Namespace: srcNamespace}, Destination: &Resource{Name: "www.google.com", Type: ResourceType_DNS}},
			{Source: &Resource{Name: src, Namespace: srcNamespace}, Destination: &Resource{Name: "www.amazon.com", Type: ResourceType_DNS}},
		})}}

	rw := &test.ResponseWriter{}
	req := new(dns.Msg)

	req.SetQuestion("www.google.com.", dns.TypeA)

	whitelistPlugin.ServeDNS(context.Background(), rw, req)

	assert.True(t, next.Served)
}

func TestWhitelist_ServeDNS_Blacklist_UnknownSvc(t *testing.T) {

	next := newMockHandler()

	const src, srcNamespace = "unknown", "ns"
	whitelistPlugin := whitelist{Kubernetes: &mockKubeAPI{}, Next: next,
		Discovery: &mockDiscovery{logged: make(chan bool, 1)},
		Zones:     []string{"cluster.local"},
		Configuration: whitelistConfig{blacklist: true, SourceToDestination: toStrictPolicy([]*PolicyRule{
			{Source: &Resource{Name: src, Namespace: srcNamespace}, Destination: &Resource{Name: "www.google.com", Type: ResourceType_DNS}},
			{Source: &Resource{Name: src, Namespace: srcNamespace}, Destination: &Resource{Name: "www.amazon.com", Type: ResourceType_DNS}},
		})}}

	rw := &test.ResponseWriter{}
	req := new(dns.Msg)

	req.SetQuestion("www.google.com.", dns.TypeA)

	whitelistPlugin.ServeDNS(context.Background(), rw, req)

	assert.True(t, next.Served)
}

func TestWhitelist_Log(t *testing.T) {

	clusterZone := "cluster.local"
	next := newMockHandler()

	const src, srcNamespace = "svc1", "testns"
	mockDiscovery := &mockDiscovery{logged: make(chan bool)}
	whitelistPlugin := whitelist{Kubernetes: &mockKubeAPI{}, Next: next,
		Discovery: mockDiscovery,
		Zones:     []string{clusterZone},
		Configuration: whitelistConfig{blacklist: true, SourceToDestination: toStrictPolicy([]*PolicyRule{
			{Source: &Resource{Name: src, Namespace: srcNamespace}, Destination: &Resource{Name: "www.google.com", Type: ResourceType_DNS}},
			{Source: &Resource{Name: src, Namespace: srcNamespace}, Destination: &Resource{Name: "www.amazon.com", Type: ResourceType_DNS}},
		})}}

	rw := &test.ResponseWriter{}
	req := new(dns.Msg)

	req.SetQuestion("www.google.com.", dns.TypeA)

	whitelistPlugin.ServeDNS(context.Background(), rw, req)
	assert.True(t, next.Served)

	select {

	case <-time.After(10 * time.Second):
		assert.Fail(t, "didn't log after timeout timeout")
	case <-mockDiscovery.logged:

	}

	assert.Len(t, mockDiscovery.discovered, 1)

	msg := mockDiscovery.discovered[0]

	type discoverMsg struct {
		Source      string `json:"src"`
		Destination string `json:"dst"`
		Action      string `json:"action"`
		Origin      string `json:"origin"`
	}

	sentMsg := discoverMsg{}
	assert.NoError(t, json.NewDecoder(bytes.NewReader(msg)).Decode(&sentMsg))

	assert.Equal(t, fmt.Sprintf("svc1.testns.svc.%s", clusterZone), sentMsg.Source)
	assert.Equal(t, "www.google.com", sentMsg.Destination)
	assert.Equal(t, "allow", sentMsg.Action)
	assert.Equal(t, "dns", sentMsg.Origin)
}

func TestWhitelist_ServeDNS_WhitelistNamespaceWildcardToEgress(t *testing.T) {

	next := newMockHandler()

	policy := []*PolicyRule{
		{
			Source:      &Resource{Namespace: "*", Type: ResourceType_KubernetesNamespace},
			Destination: &Resource{Name: "www.google.com", Type: ResourceType_DNS},
		},
	}
	whitelistPlugin := whitelist{Kubernetes: &mockKubeAPI{}, Next: next,
		Discovery: &mockDiscovery{logged: make(chan bool, 1)},
		Zones:     []string{"cluster.local"},
		Configuration: whitelistConfig{blacklist: false,
			SourceToDestination: toStrictPolicy(policy),
			WildcardRules:       getWildcardRules(policy)}}

	rw := &test.ResponseWriter{}
	req := new(dns.Msg)

	req.SetQuestion("www.google.com.", dns.TypeA)

	whitelistPlugin.ServeDNS(context.Background(), rw, req)

	assert.True(t, next.Served)
}

func TestWhitelist_ServeDNS_WhitelistNamespaceToEgress(t *testing.T) {

	next := newMockHandler()

	policy := []*PolicyRule{
		{
			Source:      &Resource{Namespace: "testns", Type: ResourceType_KubernetesNamespace},
			Destination: &Resource{Name: "www.google.com", Type: ResourceType_DNS},
		},
	}
	whitelistPlugin := whitelist{Kubernetes: &mockKubeAPI{}, Next: next,
		Discovery: &mockDiscovery{logged: make(chan bool, 1)},
		Zones:     []string{"cluster.local"},
		Configuration: whitelistConfig{blacklist: false,
			SourceToDestination: toStrictPolicy(policy),
			WildcardRules:       getWildcardRules(policy)}}

	rw := &test.ResponseWriter{}
	req := new(dns.Msg)

	req.SetQuestion("www.google.com.", dns.TypeA)

	whitelistPlugin.ServeDNS(context.Background(), rw, req)

	assert.True(t, next.Served)
}

func TestWhitelist_ServeDNS_WhitelistNamespaceToWildcardEgress(t *testing.T) {

	next := newMockHandler()

	policy := []*PolicyRule{
		{
			Source:      &Resource{Namespace: "testns", Type: ResourceType_KubernetesNamespace},
			Destination: &Resource{Name: "*.google.com", Type: ResourceType_DNS},
		},
	}
	whitelistPlugin := whitelist{Kubernetes: &mockKubeAPI{}, Next: next,
		Discovery: &mockDiscovery{logged: make(chan bool, 1)},
		Zones:     []string{"cluster.local"},
		Configuration: whitelistConfig{blacklist: false,
			SourceToDestination: toStrictPolicy(policy),
			WildcardRules:       getWildcardRules(policy)}}

	rw := &test.ResponseWriter{}
	req := new(dns.Msg)

	req.SetQuestion("www.google.com.", dns.TypeA)

	whitelistPlugin.ServeDNS(context.Background(), rw, req)

	assert.True(t, next.Served)
}
