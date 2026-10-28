package chain

// Committed format vectors, to the standard seal's formats are held to.
//
// TestVectors_VerifyCommittedTokens verifies the committed presentation
// strings DIRECTLY. It must never be replaced by minting fresh tokens and
// comparing: a round trip proves only that the code agrees with itself,
// where the whole point here is to catch a change that makes previously
// issued tokens unverifiable, or — worse — makes a token mean something
// different from what it meant when it was signed.
//
// TestVectors_AnIndependentImplementationAgrees is the other half, and it
// is what makes "a published wire format" a claim rather than a hope: a
// verifier written from docs/wire-format.md alone, using nothing but
// crypto/ed25519, crypto/sha256 and encoding/json, reaches the same verdict
// on every vector. If the document is wrong or incomplete, that test is
// where it shows.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/laenenai/captoken/caveat"
	"github.com/laenenai/captoken/domain"
)

// updateVectors regenerates testdata/vectors.json instead of checking it:
//
//	go test ./chain -run TestVectors -update-vectors
var updateVectors = flag.Bool("update-vectors", false, "rewrite testdata/vectors.json")

const vectorsPath = "testdata/vectors.json"

// vectorFile is testdata/vectors.json's shape.
type vectorFile struct {
	Comment string   `json:"_comment"`
	Vectors []vector `json:"vectors"`
}

// vector is one committed example. Everything a third-party implementation
// needs is in it: the trusted root key, the verifier's own identity, the
// resource schema, the instant to evaluate at, the presentation, the
// request, and the expected verdict.
type vector struct {
	Name          string             `json:"name"`
	Note          string             `json:"note"`
	RootPublicKey string             `json:"root_public_key_b64u"`
	Issuer        string             `json:"issuer"`
	Audience      string             `json:"audience"`
	Schema        []vectorLevel      `json:"schema"`
	NowUnix       int64              `json:"now_unix"`
	Presentation  string             `json:"presentation"`
	Request       vectorRequest      `json:"request"`
	Expect        *vectorExpectation `json:"expect,omitempty"`
	ExpectRefusal string             `json:"expect_refusal,omitempty"`
}

type vectorLevel struct {
	Name    string `json:"name"`
	Repeats bool   `json:"repeats,omitempty"`
}

type vectorRequest struct {
	Permission    string     `json:"permission"`
	Resource      [][]string `json:"resource"`
	ClientIP      string     `json:"client_ip,omitempty"`
	ContentLength int64      `json:"content_length"`
	ContentType   string     `json:"content_type,omitempty"`
}

type vectorExpectation struct {
	Type        string   `json:"type"`
	ChainID     string   `json:"chain_id"`
	Subject     string   `json:"subject"`
	Depth       int      `json:"depth"`
	Permissions []string `json:"permissions"`
	ExpiresAt   int64    `json:"expires_at"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("read %s: %v", vectorsPath, err)
	}
	var doc vectorFile
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal %s: %v", vectorsPath, err)
	}
	if len(doc.Vectors) == 0 {
		t.Fatalf("%s has no vectors", vectorsPath)
	}
	return doc
}

func (v vector) schema(t *testing.T) domain.ResourceSchema {
	t.Helper()
	kinds := make([]domain.SegmentKind, len(v.Schema))
	for i, level := range v.Schema {
		kinds[i] = domain.SegmentKind{Name: level.Name, Repeats: level.Repeats}
	}
	s, err := domain.NewResourceSchema(kinds...)
	if err != nil {
		t.Fatalf("vector %q: NewResourceSchema() error = %v", v.Name, err)
	}
	return s
}

func (v vector) rootKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(v.RootPublicKey)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		t.Fatalf("vector %q: root_public_key_b64u is not a 32-byte base64url value", v.Name)
	}
	return raw
}

func (v vector) request(t *testing.T) caveat.Request {
	t.Helper()
	segs := make([]domain.Segment, len(v.Request.Resource))
	for i, pair := range v.Request.Resource {
		if len(pair) != 2 {
			t.Fatalf("vector %q: a request resource segment is not a [kind, id] pair", v.Name)
		}
		segs[i] = domain.Segment{Kind: pair[0], ID: pair[1]}
	}
	resource, err := v.schema(t).Path(segs...)
	if err != nil {
		t.Fatalf("vector %q: the request resource is not a path the schema allows: %v", v.Name, err)
	}
	req := caveat.Request{
		Now:           time.Unix(v.NowUnix, 0).UTC(),
		Permission:    domain.Permission(v.Request.Permission),
		Resource:      resource,
		ContentLength: v.Request.ContentLength,
		ContentType:   v.Request.ContentType,
	}
	if v.Request.ClientIP != "" {
		req.ClientIP = mustAddr(t, v.Request.ClientIP)
	}
	return req
}

// TestVectors_VerifyCommittedTokens is the test that keeps
// docs/wire-format.md and this code from drifting.
func TestVectors_VerifyCommittedTokens(t *testing.T) {
	if *updateVectors {
		writeVectors(t)
		return
	}
	t.Parallel()

	for _, vec := range loadVectors(t).Vectors {
		t.Run(vec.Name, func(t *testing.T) {
			t.Parallel()

			v, err := NewVerifier(VerifierConfig{
				Issuer:       domain.Issuer(vec.Issuer),
				RootKeys:     []ed25519.PublicKey{vec.rootKey(t)},
				Audience:     domain.Audience(vec.Audience),
				Schema:       vec.schema(t),
				Clock:        domain.NewFixedClock(time.Unix(vec.NowUnix, 0).UTC()),
				NoRevocation: true,
			})
			if err != nil {
				t.Fatalf("NewVerifier() error = %v", err)
			}

			verified, err := v.Verify(t.Context(), vec.Presentation, vec.request(t))

			if vec.ExpectRefusal != "" {
				if !errors.Is(err, ErrInvalidToken) && !errors.Is(err, caveat.ErrCaveatNotSatisfied) {
					t.Fatalf("Verify() error = %v, want a refusal (%s)", err, vec.ExpectRefusal)
				}
				return
			}
			if err != nil {
				t.Fatalf("Verify(committed vector) error = %v, want nil", err)
			}
			if vec.Expect == nil {
				t.Fatal("vector expects success but commits no expectation")
			}
			if string(verified.Type) != vec.Expect.Type {
				t.Errorf("Type = %q, want %q", verified.Type, vec.Expect.Type)
			}
			if string(verified.ChainID) != vec.Expect.ChainID {
				t.Errorf("ChainID = %q, want %q", verified.ChainID, vec.Expect.ChainID)
			}
			if string(verified.Subject) != vec.Expect.Subject {
				t.Errorf("Subject = %q, want %q", verified.Subject, vec.Expect.Subject)
			}
			if verified.Depth != vec.Expect.Depth {
				t.Errorf("Depth = %d, want %d", verified.Depth, vec.Expect.Depth)
			}
			if verified.ExpiresAt.Unix() != vec.Expect.ExpiresAt {
				t.Errorf("ExpiresAt = %d, want %d", verified.ExpiresAt.Unix(), vec.Expect.ExpiresAt)
			}
			got := make([]string, 0, len(verified.Permissions))
			for _, p := range verified.Permissions.Sorted() {
				got = append(got, string(p))
			}
			if !slices.Equal(got, vec.Expect.Permissions) {
				t.Errorf("Permissions = %v, want %v", got, vec.Expect.Permissions)
			}
		})
	}
}

// TestVectors_AnIndependentImplementationAgrees verifies every vector with
// a verifier written from docs/wire-format.md alone.
//
// It deliberately shares NO code with the implementation above — no
// splitPresentation, no decodeLink, no go-jose — and uses only
// crypto/ed25519, crypto/sha256 and encoding/json, which is what a
// third-party implementer in any language has. It implements the four
// checks the format document names as a third-party verifier's contract,
// plus the chain walk, and nothing else.
//
// This is the test that makes "a published wire format with test vectors" a
// claim about the document rather than about this package.
func TestVectors_AnIndependentImplementationAgrees(t *testing.T) {
	t.Parallel()

	for _, vec := range loadVectors(t).Vectors {
		t.Run(vec.Name, func(t *testing.T) {
			t.Parallel()

			err := independentVerify(vec.Presentation, vec.rootKey(t), vec.Issuer, vec.Audience, vec.NowUnix)
			switch {
			case vec.ExpectRefusal != "" && vec.ExpectRefusal != "the request is not permitted":
				// Every refusal except a request-level one is a refusal an
				// independent implementation must also reach: the chain is
				// not well formed.
				if err == nil {
					t.Fatalf("an independent implementation ACCEPTED a vector that must be refused (%s)", vec.ExpectRefusal)
				}
			case vec.ExpectRefusal != "":
				// A request-level refusal is outside the four checks this
				// minimal verifier performs; it must find the chain itself
				// sound.
				if err != nil {
					t.Fatalf("an independent implementation rejected a well-formed chain: %v", err)
				}
			default:
				if err != nil {
					t.Fatalf("an independent implementation rejected a valid vector: %v\n"+
						"docs/wire-format.md is wrong or incomplete", err)
				}
			}
		})
	}
}

// independentVerify is the whole of a third-party verifier, written from
// the format document. It performs the chain walk (signature per link under
// the key its parent bound, par_hash per link), the format version, the
// algorithm and media type, the issuer and chain id, the token types, exp
// and nbf, the audience, and subsumption.
//
// It stops short in exactly one documented place: subsumption of the caveat
// ARRAY is checked only as "every kind the parent carries is restated by
// the child", not as a per-kind narrowing comparison, because that
// comparison is per-kind and writing sixteen of them here would duplicate
// the implementation rather than test the document. The format document
// names that comparison as part of a verifier's obligations, and the
// per-kind semantics are tested by caveat.Narrows and by the adversarial
// suite. Everything else below is the document, read once and implemented.
//
// It does NOT evaluate the caveat array against the REQUEST, which is what
// a deliberately incomplete verifier looks like — and the format's
// soundness claim is that such a verifier is right about everything it did
// check.
func independentVerify(presented string, rootKey ed25519.PublicKey, issuer, audience string, nowUnix int64) error {
	const (
		prefix   = "ct1~"
		sep      = "~"
		wantAlg  = "EdDSA"
		wantTyp  = "captoken+jwt"
		wantCtv  = 1.0
		skewSecs = 60
		maxLinks = 8
	)
	if !strings.HasPrefix(presented, prefix) {
		return errors.New("not a captoken presentation")
	}
	links := strings.Split(strings.TrimPrefix(presented, prefix), sep)
	if len(links) == 0 || len(links) > maxLinks {
		return errors.New("chain length out of range")
	}

	type decoded struct {
		compact string
		signing string
		claims  map[string]any
	}
	out := make([]decoded, len(links))
	for i, compact := range links {
		parts := strings.Split(compact, ".")
		if len(parts) != 3 {
			return errors.New("not a compact JWS")
		}
		headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			return errors.New("header is not base64url")
		}
		var hdr map[string]any
		if err := json.Unmarshal(headerBytes, &hdr); err != nil {
			return errors.New("header is not a JSON object")
		}
		if len(hdr) != 2 || hdr["alg"] != wantAlg || hdr["typ"] != wantTyp {
			return errors.New("header is not exactly {alg: EdDSA, typ: captoken+jwt}")
		}
		payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return errors.New("payload is not base64url")
		}
		var c map[string]any
		if err := json.Unmarshal(payloadBytes, &c); err != nil {
			return errors.New("payload is not a JSON object")
		}
		if c["ctv"] != wantCtv {
			return errors.New("unsupported format version")
		}
		out[i] = decoded{compact: compact, signing: parts[0] + "." + parts[1], claims: c}
	}

	for i, l := range out {
		sigBytes, err := base64.RawURLEncoding.DecodeString(l.compact[strings.LastIndex(l.compact, ".")+1:])
		if err != nil {
			return errors.New("signature is not base64url")
		}

		var key ed25519.PublicKey
		if i == 0 {
			key = rootKey
			if _, present := l.claims["par_hash"]; present {
				return errors.New("the root link names a parent")
			}
		} else {
			parent := out[i-1]
			cnf, ok := parent.claims["cnf"].(map[string]any)
			if !ok {
				return errors.New("the parent binds no key")
			}
			jwk, ok := cnf["jwk"].(map[string]any)
			if !ok || jwk["kty"] != "OKP" || jwk["crv"] != "Ed25519" {
				return errors.New("the parent's bound key is not an Ed25519 OKP key")
			}
			x, ok := jwk["x"].(string)
			if !ok {
				return errors.New("the parent's bound key has no x")
			}
			raw, derr := base64.RawURLEncoding.DecodeString(x)
			if derr != nil || len(raw) != ed25519.PublicKeySize {
				return errors.New("the parent's bound key is malformed")
			}
			key = raw

			sum := sha256.Sum256([]byte(parent.signing))
			if l.claims["par_hash"] != base64.RawURLEncoding.EncodeToString(sum[:]) {
				return errors.New("parent hash mismatch")
			}
		}
		if !ed25519.Verify(key, []byte(l.signing), sigBytes) {
			return errors.New("signature does not verify")
		}

		if l.claims["iss"] != issuer {
			return errors.New("issuer mismatch")
		}
		if l.claims["cid"] != out[0].claims["jti"] {
			return errors.New("chain id is not the root link's token id")
		}
		if i < len(out)-1 && l.claims["ctt"] != "delegation" {
			return errors.New("an interior link is not a delegation token")
		}

		if i > 0 {
			if err := independentSubsumes(l.claims, out[i-1].claims); err != nil {
				return err
			}
		}

		exp, ok := l.claims["exp"].(float64)
		if !ok {
			return errors.New("no expiry")
		}
		if float64(nowUnix) > exp+skewSecs {
			return errors.New("expired")
		}
		if nbf, has := l.claims["nbf"].(float64); has && float64(nowUnix) < nbf-skewSecs {
			return errors.New("not yet valid")
		}
	}

	leaf := out[len(out)-1]
	if leaf.claims["ctt"] != "execution" && leaf.claims["ctt"] != "redemption" {
		return errors.New("the terminal link authorises no operation")
	}
	auds, ok := leaf.claims["aud"].([]any)
	if !ok {
		return errors.New("the terminal link names no audience")
	}
	if !slices.Contains(auds, any(audience)) {
		return errors.New("not this audience")
	}
	return nil
}

// ---- generation -----------------------------------------------------------

// vectorSeeds are the fixed Ed25519 seeds the vectors are built from, so
// that regenerating them reproduces the same keys and therefore the same
// tokens. Seed 0 is the root key; the others are the keys each delegation
// link binds.
var vectorSeeds = [][]byte{
	bytes.Repeat([]byte{0x11}, ed25519.SeedSize),
	bytes.Repeat([]byte{0x22}, ed25519.SeedSize),
	bytes.Repeat([]byte{0x33}, ed25519.SeedSize),
}

// writeVectors regenerates testdata/vectors.json.
//
// The links are assembled claim set by claim set, with fixed ids and fixed
// instants, rather than by calling Mint and Derive. That is deliberate: a
// vector built by the minter can only ever agree with the minter, whereas
// one built from the format document's own description of a claim set is a
// statement about the format.
func writeVectors(t *testing.T) {
	t.Helper()

	keys := make([]KeyPair, len(vectorSeeds))
	for i, seed := range vectorSeeds {
		priv := ed25519.NewKeyFromSeed(seed)
		pub, ok := priv.Public().(ed25519.PublicKey)
		if !ok {
			t.Fatal("ed25519 private key did not yield a public key")
		}
		keys[i] = KeyPair{Public: pub, Private: priv}
	}

	const (
		iss      = "vectors.example"
		gateway  = "gateway.example"
		rootID   = "AAAAAAAAAAAAAAAAAAAAAA"
		midID    = "BBBBBBBBBBBBBBBBBBBBBB"
		leafID   = "CCCCCCCCCCCCCCCCCCCCCC"
		iat      = int64(1_792_000_000) // 2026-10-13T18:13:20Z
		rootExp  = iat + 86400
		midExp   = iat + 43200
		leafExp  = iat + 3600
		evalTime = iat + 60
	)

	jwk := func(i int) *confirmation {
		raw, err := encodeJWK(keys[i].Public)
		if err != nil {
			t.Fatalf("encodeJWK() error = %v", err)
		}
		return &confirmation{JWK: raw}
	}
	cav := func(caveats ...caveat.Caveat) []caveat.WireCaveat {
		entries, err := caveat.EncodeAll(caveats)
		if err != nil {
			t.Fatalf("EncodeAll() error = %v", err)
		}
		return entries
	}

	nbf := int64(iat)
	rootClaims := claims{
		Version: FormatVersion, Type: string(TypeDelegation), Issuer: iss, Subject: "holder-1",
		Audience: []string{gateway}, TokenID: rootID, ChainID: rootID,
		IssuedAt: iat, ExpiresAt: rootExp,
		Permissions: []string{"doc.read_content", "doc.write_content"},
		Resources:   [][][]string{{{"tenant", "t1"}}},
		Caveats: cav(
			caveat.MaxContentLength(1<<20),
			caveat.ClientCIDR(mustPrefix(t, "10.0.0.0/8")),
		),
		Confirmation: jwk(1),
	}
	rootToken, err := signLink(rootClaims, keys[0].Private)
	if err != nil {
		t.Fatalf("signLink(root) error = %v", err)
	}

	midClaims := claims{
		Version: FormatVersion, Type: string(TypeDelegation), Issuer: iss, Subject: "holder-2",
		Audience: []string{gateway}, TokenID: midID, ChainID: rootID,
		IssuedAt: iat, NotBefore: &nbf, ExpiresAt: midExp,
		Permissions: []string{"doc.read_content"},
		Resources:   [][][]string{{{"tenant", "t1"}, {"fileset", "a"}}},
		Caveats: cav(
			caveat.MaxContentLength(1<<16),
			caveat.ClientCIDR(mustPrefix(t, "10.1.0.0/16")),
		),
		Confirmation: jwk(2),
		ParentHash:   ptr(parentHash(signingInput(rootToken))),
	}
	midToken, err := signLink(midClaims, keys[1].Private)
	if err != nil {
		t.Fatalf("signLink(middle) error = %v", err)
	}

	leafClaims := claims{
		Version: FormatVersion, Type: string(TypeExecution), Issuer: iss, Subject: "holder-3",
		Audience: []string{gateway}, TokenID: leafID, ChainID: rootID,
		IssuedAt: iat, NotBefore: &nbf, ExpiresAt: leafExp,
		Permissions: []string{"doc.read_content"},
		Resources:   [][][]string{{{"tenant", "t1"}, {"fileset", "a"}, {"document", "d1"}}},
		Caveats: cav(
			caveat.MaxContentLength(1<<10),
			caveat.ClientCIDR(mustPrefix(t, "10.1.2.0/24")),
		),
		ParentHash: ptr(parentHash(signingInput(midToken))),
	}
	leafToken, err := signLink(leafClaims, keys[2].Private)
	if err != nil {
		t.Fatalf("signLink(leaf) error = %v", err)
	}

	// A single-link execution token, the smallest useful chain.
	soloClaims := leafClaims
	soloClaims.TokenID = rootID
	soloClaims.ChainID = rootID
	soloClaims.ParentHash = nil
	soloToken, err := signLink(soloClaims, keys[0].Private)
	if err != nil {
		t.Fatalf("signLink(solo) error = %v", err)
	}

	// A widening leaf: the same chain with the terminal link re-signed to
	// claim a permission its parent never granted. Committed so that a
	// third-party implementation can prove it refuses one.
	wideClaims := leafClaims
	wideClaims.Permissions = []string{"doc.read_content", "doc.write_content"}
	wideToken, err := signLink(wideClaims, keys[2].Private)
	if err != nil {
		t.Fatalf("signLink(widened leaf) error = %v", err)
	}

	schema := []vectorLevel{
		{Name: "tenant"},
		{Name: "fileset", Repeats: true},
		{Name: "document"},
		{Name: "slot"},
		{Name: "element"},
	}
	rootKeyB64 := base64.RawURLEncoding.EncodeToString(keys[0].Public)
	req := vectorRequest{
		Permission:    "doc.read_content",
		Resource:      [][]string{{"tenant", "t1"}, {"fileset", "a"}, {"document", "d1"}},
		ClientIP:      "10.1.2.3",
		ContentLength: 512,
		ContentType:   "application/pdf",
	}

	doc := vectorFile{
		Comment: "Committed captoken format vectors, pinning docs/wire-format.md. " +
			"TestVectors_VerifyCommittedTokens verifies these presentation strings DIRECTLY; it must " +
			"never be replaced by minting fresh tokens and comparing, since a round trip proves only " +
			"that the code agrees with itself. TestVectors_AnIndependentImplementationAgrees verifies " +
			"them again with a verifier written from the document alone, using nothing but " +
			"crypto/ed25519, crypto/sha256 and encoding/json. The keys come from the fixed seeds in " +
			"vectors_test.go (0x11, 0x22, 0x33 repeated), so regenerating reproduces the same tokens. " +
			"More than one vector is committed deliberately: a single-link chain cannot distinguish a " +
			"broken par_hash, a broken cnf linkage or a broken subsumption check from a correct " +
			"implementation, and a chain with no refusal vector cannot show that a widening is caught.",
		Vectors: []vector{
			{
				Name:          "single_link_execution_token",
				Note:          "The smallest useful chain: one execution token signed by the root key, with no par_hash and no cnf.",
				RootPublicKey: rootKeyB64,
				Issuer:        iss,
				Audience:      gateway,
				Schema:        schema,
				NowUnix:       evalTime,
				Presentation:  present([]string{soloToken}),
				Request:       req,
				Expect: &vectorExpectation{
					Type: "execution", ChainID: rootID, Subject: "holder-3", Depth: 1,
					Permissions: []string{"doc.read_content"}, ExpiresAt: leafExp,
				},
			},
			{
				Name: "three_link_delegation_to_execution",
				Note: "delegation -> delegation -> execution. Exercises par_hash at two depths, the cnf key " +
					"chain, nbf, and narrowing in permissions, resources, expiry and two caveat kinds.",
				RootPublicKey: rootKeyB64,
				Issuer:        iss,
				Audience:      gateway,
				Schema:        schema,
				NowUnix:       evalTime,
				Presentation:  present([]string{rootToken, midToken, leafToken}),
				Request:       req,
				Expect: &vectorExpectation{
					Type: "execution", ChainID: rootID, Subject: "holder-3", Depth: 3,
					Permissions: []string{"doc.read_content"}, ExpiresAt: leafExp,
				},
			},
			{
				Name:          "refusal_truncated_to_a_delegation_prefix",
				Note:          "A proper prefix of the chain above. Its terminal link is a delegation token, which authorises no operation.",
				RootPublicKey: rootKeyB64,
				Issuer:        iss,
				Audience:      gateway,
				Schema:        schema,
				NowUnix:       evalTime,
				Presentation:  present([]string{rootToken, midToken}),
				Request:       req,
				ExpectRefusal: "the terminal link authorises no operation",
			},
			{
				Name:          "refusal_widened_terminal_link",
				Note:          "The three-link chain with its terminal link re-signed to claim doc.write_content, which its parent never granted.",
				RootPublicKey: rootKeyB64,
				Issuer:        iss,
				Audience:      gateway,
				Schema:        schema,
				NowUnix:       evalTime,
				Presentation:  present([]string{rootToken, midToken, wideToken}),
				Request:       req,
				ExpectRefusal: "the terminal link widens its parent's permissions",
			},
			{
				Name:          "refusal_middle_link_removed",
				Note:          "The three-link chain with its middle link dropped, so the terminal link's par_hash and signing key both belong to a link that is not there.",
				RootPublicKey: rootKeyB64,
				Issuer:        iss,
				Audience:      gateway,
				Schema:        schema,
				NowUnix:       evalTime,
				Presentation:  present([]string{rootToken, leafToken}),
				Request:       req,
				ExpectRefusal: "the chain is not contiguous",
			},
		},
	}

	raw, err := json.MarshalIndent(doc, "", " ")
	if err != nil {
		t.Fatalf("marshal vectors: %v", err)
	}
	raw = append(raw, '\n')
	if err := os.MkdirAll("testdata", 0o750); err != nil {
		t.Fatalf("mkdir testdata: %v", err)
	}
	if err := os.WriteFile(vectorsPath, raw, 0o600); err != nil {
		t.Fatalf("write %s: %v", vectorsPath, err)
	}
	t.Logf("%s rewritten", vectorsPath)
}

// independentSubsumes is the subsumption rule, implemented from the format
// document against the raw claim maps. See independentVerify for the one
// part it leaves out and why.
func independentSubsumes(child, parent map[string]any) error {
	childPrm, cok := stringList(child["prm"])
	parentPrm, pok := stringList(parent["prm"])
	if !cok || !pok {
		return errors.New("a link grants no permission")
	}
	for _, p := range childPrm {
		if !slices.Contains(parentPrm, p) {
			return errors.New("permissions widen")
		}
	}

	childRes, cok := pathList(child["res"])
	parentRes, pok := pathList(parent["res"])
	if !cok || !pok || len(childRes) == 0 || len(parentRes) == 0 {
		return errors.New("a link names no resource")
	}
	for _, scope := range childRes {
		contained := false
		for _, outer := range parentRes {
			if segmentPrefix(outer, scope) {
				contained = true
				break
			}
		}
		if !contained {
			return errors.New("resource scope widens")
		}
	}

	childExp, cok := child["exp"].(float64)
	parentExp, pok := parent["exp"].(float64)
	if !cok || !pok || childExp > parentExp {
		return errors.New("validity window widens")
	}
	parentNbf, hasParentNbf := parent["nbf"].(float64)
	if hasParentNbf {
		childNbf, hasChildNbf := child["nbf"].(float64)
		if !hasChildNbf || childNbf < parentNbf {
			return errors.New("validity window widens")
		}
	}

	if parentAud, has := stringList(parent["aud"]); has && len(parentAud) > 0 {
		childAud, hasChild := stringList(child["aud"])
		if !hasChild || len(childAud) == 0 {
			return errors.New("audience widens")
		}
		for _, a := range childAud {
			if !slices.Contains(parentAud, a) {
				return errors.New("audience widens")
			}
		}
	}

	for _, kind := range caveatKinds(parent["cav"]) {
		if !slices.Contains(caveatKinds(child["cav"]), kind) {
			return errors.New("a caveat was dropped")
		}
	}
	return nil
}

func stringList(v any) ([]string, bool) {
	raw, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(raw))
	for _, e := range raw {
		s, sok := e.(string)
		if !sok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

func pathList(v any) ([][][2]string, bool) {
	raw, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([][][2]string, 0, len(raw))
	for _, p := range raw {
		segsRaw, sok := p.([]any)
		if !sok {
			return nil, false
		}
		segs := make([][2]string, 0, len(segsRaw))
		for _, segRaw := range segsRaw {
			pair, pok := stringList(segRaw)
			if !pok || len(pair) != 2 {
				return nil, false
			}
			segs = append(segs, [2]string{pair[0], pair[1]})
		}
		out = append(out, segs)
	}
	return out, true
}

// segmentPrefix is the format document's containment rule: outer contains
// inner exactly when outer's segments are an element-wise prefix of
// inner's, each (kind, id) pair compared for exact equality. Never a string
// prefix — that is the bug the structured encoding exists to prevent.
func segmentPrefix(outer, inner [][2]string) bool {
	if len(outer) > len(inner) {
		return false
	}
	for i := range outer {
		if outer[i] != inner[i] {
			return false
		}
	}
	return true
}

func caveatKinds(v any) []string {
	raw, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, e := range raw {
		entry, eok := e.(map[string]any)
		if !eok {
			continue
		}
		if kind, kok := entry["k"].(string); kok {
			out = append(out, kind)
		}
	}
	return out
}
