package config

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/p2p/net/swarm"
)

func TestAutoNATServiceDialerSelection(t *testing.T) {
	injected := network.Network((*swarm.Swarm)(nil))

	t.Run("injected network is selected", func(t *testing.T) {
		cfg := Config{AutoNATConfig: AutoNATConfig{
			EnableService: true,
			ServiceDialer: injected,
		}}
		got, err := cfg.autoNATServiceDialer()
		if err != nil {
			t.Fatal(err)
		}
		if got != injected {
			t.Fatal("expected injected AutoNAT service dialer to be selected")
		}
	})

	t.Run("EnableService without dialer selects default construction", func(t *testing.T) {
		cfg := Config{AutoNATConfig: AutoNATConfig{EnableService: true}}
		if cfg.AutoNATConfig.ServiceDialer != nil {
			t.Fatal("EnableNATService should leave ServiceDialer unset so the default auxiliary swarm is constructed")
		}
	})
}

func TestNilOption(t *testing.T) {
	var cfg Config
	optsRun := 0
	opt := func(_ *Config) error {
		optsRun++
		return nil
	}
	if err := cfg.Apply(nil); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Apply(opt, nil, nil, opt, opt, nil); err != nil {
		t.Fatal(err)
	}
	if optsRun != 3 {
		t.Fatalf("expected to have handled 3 options, handled %d", optsRun)
	}
}
