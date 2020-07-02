package whitelist

import (
	"context"
	"errors"
	"testing"

	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	api "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const svc, svcNamespace, googleQuestion, googleCom, cnnQuestion = "svc1", "testns", "www.google.com.", "www.google.com", "www.cnn.com."

var srcToDst, _ = getPolicy([]*PolicyRule{
	{Source: &Resource{Name: svc, Namespace: svcNamespace}, Destination: &Resource{Name: googleCom, Type: ResourceType_DNS}},
	{Source: &Resource{Name: svc, Namespace: svcNamespace}, Destination: &Resource{Name: "www.amazon.com", Type: ResourceType_DNS}},
})

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
				Name:      svc,
				Namespace: svcNamespace,
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
				Namespace: svcNamespace,
			},
			Spec: api.ServiceSpec{
				ClusterIP: api.ClusterIPNone,
				Selector:  map[string]string{"app": "test2"},
			},
		},
		{
			ObjectMeta: meta.ObjectMeta{
				Name:      "external",
				Namespace: svcNamespace,
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

	if name == svcNamespace {
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

	req.SetQuestion(googleQuestion, dns.TypeA)

	whitelistPlugin.ServeDNS(context.Background(), rw, req)

	assert.False(t, next.Served)
}

func TestWhitelist_ServeDNS_ConfiguredNotWhitelisted(t *testing.T) {

	next := newMockHandler()

	whitelistPlugin := whitelist{Kubernetes: &mockKubeAPI{}, Next: next,
		Discovery:     &mockDiscovery{logged: make(chan bool, 1)},
		Zones:         []string{"cluster.local"},
		Configuration: whitelistConfig{blacklist: false, SourceToDestination: srcToDst}}

	rw := &test.ResponseWriter{}
	req := new(dns.Msg)

	req.SetQuestion("www.google2.com.", dns.TypeA)

	whitelistPlugin.ServeDNS(context.Background(), rw, req)

	assert.False(t, next.Served)
}

func TestWhitelist_ServeDNS_Whitelisted(t *testing.T) {

	next := newMockHandler()

	whitelistPlugin := whitelist{Kubernetes: &mockKubeAPI{}, Next: next,
		Discovery:     &mockDiscovery{logged: make(chan bool, 1)},
		Zones:         []string{"cluster.local"},
		Configuration: whitelistConfig{blacklist: true, SourceToDestination: srcToDst}}

	rw := &test.ResponseWriter{}
	req := new(dns.Msg)

	req.SetQuestion(googleQuestion, dns.TypeA)

	whitelistPlugin.ServeDNS(context.Background(), rw, req)

	assert.True(t, next.Served)
}

func TestWhitelist_ServeDNS_Blacklist_UnknownSvc(t *testing.T) {

	next := newMockHandler()

	const srcUnknown, srcNamespaceUnknown = "unknown", "ns"
	srcToDstUnknown, wildcardRules := getPolicy([]*PolicyRule{
		{Source: &Resource{Name: srcUnknown, Namespace: srcNamespaceUnknown}, Destination: &Resource{Name: googleCom, Type: ResourceType_DNS}},
		{Source: &Resource{Name: srcUnknown, Namespace: srcNamespaceUnknown}, Destination: &Resource{Name: "www.amazon.com", Type: ResourceType_DNS}},
	})
	assert.Empty(t, wildcardRules)
	whitelistPlugin := whitelist{Kubernetes: &mockKubeAPI{}, Next: next,
		Discovery:     &mockDiscovery{logged: make(chan bool, 1)},
		Zones:         []string{"cluster.local"},
		Configuration: whitelistConfig{blacklist: true, SourceToDestination: srcToDstUnknown}}

	rw := &test.ResponseWriter{}
	req := new(dns.Msg)

	req.SetQuestion(googleQuestion, dns.TypeA)

	whitelistPlugin.ServeDNS(context.Background(), rw, req)

	assert.True(t, next.Served)
}

func TestWhitelist_ServeDNS_WhitelistNamespaceWildcardToEgress(t *testing.T) {

	assert.True(t, testServeDNS([]*PolicyRule{
		{
			Source:      &Resource{Namespace: "*", Type: ResourceType_KubernetesNamespace},
			Destination: &Resource{Name: googleCom, Type: ResourceType_DNS},
		},
	}, googleQuestion))
}

func TestWhitelist_ServeDNS_WhitelistNamespaceWildcardToEgress_NotMatch(t *testing.T) {

	assert.False(t, testServeDNS([]*PolicyRule{
		{
			Source:      &Resource{Namespace: "*", Type: ResourceType_KubernetesNamespace},
			Destination: &Resource{Name: googleCom, Type: ResourceType_DNS},
		},
	}, cnnQuestion))
}

func TestWhitelist_ServeDNS_WhitelistNamespaceToEgress(t *testing.T) {

	assert.True(t, testServeDNS([]*PolicyRule{
		{
			Source:      &Resource{Namespace: svcNamespace, Type: ResourceType_KubernetesNamespace},
			Destination: &Resource{Name: googleCom, Type: ResourceType_DNS},
		},
	}, googleQuestion))
}

func TestWhitelist_ServeDNS_WhitelistNamespaceToEgress_NotMatch(t *testing.T) {

	assert.False(t, testServeDNS([]*PolicyRule{
		{
			Source:      &Resource{Namespace: svcNamespace, Type: ResourceType_KubernetesNamespace},
			Destination: &Resource{Name: googleCom, Type: ResourceType_DNS},
		},
	}, cnnQuestion))
}

func TestWhitelist_ServeDNS_WhitelistNamespaceToWildcardEgress(t *testing.T) {

	assert.True(t, testServeDNS([]*PolicyRule{
		{
			Source:      &Resource{Namespace: svcNamespace, Type: ResourceType_KubernetesNamespace},
			Destination: &Resource{Name: "*.google.com", Type: ResourceType_DNS},
		},
	}, googleQuestion))
}

func TestWhitelist_ServeDNS_WhitelistNamespaceToWildcardEgress_NotMatch(t *testing.T) {

	assert.False(t, testServeDNS([]*PolicyRule{
		{
			Source:      &Resource{Namespace: svcNamespace, Type: ResourceType_KubernetesNamespace},
			Destination: &Resource{Name: "*.google.com", Type: ResourceType_DNS},
		},
	}, cnnQuestion))
}

func testServeDNS(policy []*PolicyRule, question string) bool {

	next := newMockHandler()
	srcToDst, wildcardRules := getPolicy(policy)
	whitelistPlugin := whitelist{Kubernetes: &mockKubeAPI{}, Next: next,
		Discovery: &mockDiscovery{logged: make(chan bool, 1)},
		Zones:     []string{"cluster.local"},
		Configuration: whitelistConfig{blacklist: false,
			SourceToDestination: srcToDst,
			WildcardRules:       wildcardRules}}
	log.Infof("%+v", whitelistPlugin.Configuration)
	rw := &test.ResponseWriter{}
	req := new(dns.Msg)
	req.SetQuestion(question, dns.TypeA)
	whitelistPlugin.ServeDNS(context.Background(), rw, req)

	return next.Served
}
