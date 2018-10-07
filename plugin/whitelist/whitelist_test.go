package whitelist

import (
	"context"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	api "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"
)

type mockHandler struct {
	Served bool
}

func newMockHandler() *mockHandler { return &mockHandler{Served: false} }

func (mh *mockHandler) ServeDNS(context.Context, dns.ResponseWriter, *dns.Msg) (int, error) {
	mh.Served = true
	return 1, nil
}

func (mh mockHandler) Name() string {
	return "mockHandler"
}

type mockKubeAPI struct {
}

func (mk mockKubeAPI) ServiceList() []*api.Service {
	svcs := []*api.Service{
		{
			ObjectMeta: meta.ObjectMeta{
				Name:      "svc1",
				Namespace: "testns",
				Labels:    map[string]string{"app": "test"},
			},
			Spec: api.ServiceSpec{
				ClusterIP: "10.0.0.1",
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
				Labels:    map[string]string{"app": "test2"},
			},
			Spec: api.ServiceSpec{
				ClusterIP: api.ClusterIPNone,
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
	return svcs
}

func (mk mockKubeAPI) GetNamespaceByName(name string) (*api.Namespace, error) {
	return &api.Namespace{
		ObjectMeta: meta.ObjectMeta{
			Name: name,
		},
	}, nil
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
		Discovery:     nil,
		Zones:         []string{"cluster.local"},
		Configuration: whitelistConfig{blacklist: false}}

	rw := &test.ResponseWriter{}
	req := new(dns.Msg)

	req.SetQuestion("www.google.com", dns.TypeA)

	whitelistPlugin.ServeDNS(context.Background(), rw, req)

	assert.False(t, next.Served)

}

func TestWhitelist_ServeDNS_Whitelisted(t *testing.T) {

	next := newMockHandler()

	config := make(map[string][]string)
	config["svc1.testns"] = []string{"www.google.com", "www.amazon.com"}

	whitelistPlugin := whitelist{Kubernetes: &mockKubeAPI{}, Next: next,
		Discovery:     nil,
		Zones:         []string{"cluster.local"},
		Configuration: whitelistConfig{blacklist: true, SourceToDestination: convert(config)}}

	rw := &test.ResponseWriter{}
	req := new(dns.Msg)

	req.SetQuestion("www.google.com", dns.TypeA)

	whitelistPlugin.ServeDNS(context.Background(), rw, req)

	assert.True(t, next.Served)
}
