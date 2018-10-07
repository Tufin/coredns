package whitelist

import (
	"context"
	"github.com/coredns/coredns/plugin/kubernetes"
	"github.com/coredns/coredns/plugin/pkg/watch"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
	api "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"
	"time"
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

type APIConnServeTest struct{}

func (APIConnServeTest) HasSynced() bool                        { return true }
func (APIConnServeTest) Run()                                   { return }
func (APIConnServeTest) Stop() error                            { return nil }
func (APIConnServeTest) EpIndexReverse(string) []*api.Endpoints { return nil }
func (APIConnServeTest) SvcIndexReverse(string) []*api.Service  { return nil }
func (APIConnServeTest) Modified() int64                        { return time.Now().Unix() }
func (APIConnServeTest) SetWatchChan(watch.Chan)                {}
func (APIConnServeTest) Watch(string) error                     { return nil }
func (APIConnServeTest) StopWatching(string)                    {}

func (APIConnServeTest) PodIndex(string) []*api.Pod {
	a := []*api.Pod{{
		ObjectMeta: meta.ObjectMeta{
			Namespace: "podns",
		},
		Status: api.PodStatus{
			PodIP: "10.240.0.1", // Remote IP set in test.ResponseWriter
		},
	}}
	return a
}

var svcIndex = map[string][]*api.Service{
	"svc1.testns": {{
		ObjectMeta: meta.ObjectMeta{
			Name:      "svc1",
			Namespace: "testns",
		},
		Spec: api.ServiceSpec{
			Type:      api.ServiceTypeClusterIP,
			ClusterIP: "10.0.0.1",
			Ports: []api.ServicePort{{
				Name:     "http",
				Protocol: "tcp",
				Port:     80,
			}},
		},
	}},
	"svcempty.testns": {{
		ObjectMeta: meta.ObjectMeta{
			Name:      "svcempty",
			Namespace: "testns",
		},
		Spec: api.ServiceSpec{
			Type:      api.ServiceTypeClusterIP,
			ClusterIP: "10.0.0.1",
			Ports: []api.ServicePort{{
				Name:     "http",
				Protocol: "tcp",
				Port:     80,
			}},
		},
	}},
	"svc6.testns": {{
		ObjectMeta: meta.ObjectMeta{
			Name:      "svc6",
			Namespace: "testns",
		},
		Spec: api.ServiceSpec{
			Type:      api.ServiceTypeClusterIP,
			ClusterIP: "1234:abcd::1",
			Ports: []api.ServicePort{{
				Name:     "http",
				Protocol: "tcp",
				Port:     80,
			}},
		},
	}},
	"hdls1.testns": {{
		ObjectMeta: meta.ObjectMeta{
			Name:      "hdls1",
			Namespace: "testns",
		},
		Spec: api.ServiceSpec{
			Type:      api.ServiceTypeClusterIP,
			ClusterIP: api.ClusterIPNone,
		},
	}},
	"external.testns": {{
		ObjectMeta: meta.ObjectMeta{
			Name:      "external",
			Namespace: "testns",
		},
		Spec: api.ServiceSpec{
			ExternalName: "ext.interwebs.test",
			Ports: []api.ServicePort{{
				Name:     "http",
				Protocol: "tcp",
				Port:     80,
			}},
			Type: api.ServiceTypeExternalName,
		},
	}},
}

func TestWhitelist_ServeDNS(t *testing.T) {

	k8s := kubernetes.New([]string{"cluster.local"})

	whitelistPlugin := &whitelist{Kubernetes: k8s, Next: newMockHandler(),
		Discovery:     nil,
		Configuration: whitelistConfig{}}

	rw := &test.ResponseWriter{}
	req := new(dns.Msg)

	req.SetQuestion("www.google.com", dns.TypeA)

	whitelistPlugin.ServeDNS(context.Background(), rw, req)

}
