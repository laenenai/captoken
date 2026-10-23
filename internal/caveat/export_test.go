package caveat

// unregisterForTest removes a kind from the registry.
//
// It is deliberately test-only. There is no production reason to remove a
// kind — the vocabulary is part of the published wire format, and a build
// that can forget a kind at run time is a build whose verification result
// depends on when it is asked. The one caller is the test that registers a
// deliberately broken decoder and must leave the registry as it found it,
// since the registry is global.
func unregisterForTest(kind string) {
	registryMu.Lock()
	defer registryMu.Unlock()
	delete(registry, kind)
}

// UnregisterCaveatForTest is unregisterForTest, reachable from the external
// caveat_test package.
var UnregisterCaveatForTest = unregisterForTest
