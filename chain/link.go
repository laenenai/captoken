package chain

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"

	"github.com/laenenai/captoken/caveat"
	"github.com/laenenai/captoken/domain"
)

// claims is one link's JWT claim set, in the exact member order it is
// serialized in.
//
// The order is this struct's declaration order, because encoding/json
// writes struct fields in declaration order. That is deliberate and it is
// load-bearing: the claim set is signed bytes, so a canonical order is what
// makes a token reproducible, and a map would have given Go's randomized
// iteration order instead. docs/wire-format.md states the same order, and
// testdata/vectors.json pins it.
type claims struct {
	// Version is "ctv", the format version. A verifier refuses a version
	// it does not implement.
	Version int `json:"ctv"`
	// Type is "ctt", the token type. See TokenType.
	Type string `json:"ctt"`
	// Issuer is "iss", opaque.
	Issuer string `json:"iss"`
	// Subject is "sub", opaque. It is the one dimension this module does
	// not order: delegating to another holder is what a delegation token
	// is for, and nothing here can rank two opaque ids.
	Subject string `json:"sub"`
	// Audience is "aud". Required on a terminal link and the claim the
	// partition's soundness rests on.
	Audience []string `json:"aud,omitempty"`
	// TokenID is "jti", unique per link. The root link's is the chain's
	// identifier.
	TokenID string `json:"jti"`
	// ChainID is "cid": the root link's jti, carried verbatim by every
	// descendant, so one revocation record kills a whole chain.
	ChainID string `json:"cid"`
	// IssuedAt is "iat", whole seconds.
	IssuedAt int64 `json:"iat"`
	// NotBefore is "nbf", whole seconds, optional. A pointer rather than a
	// zero value so that "no lower bound" and "the epoch" are different
	// tokens.
	NotBefore *int64 `json:"nbf,omitempty"`
	// ExpiresAt is "exp", whole seconds, REQUIRED. A capability with no
	// expiry is a liability, and requiring it also means the subsumption
	// rule never has to reason about a missing bound.
	ExpiresAt int64 `json:"exp"`
	// Permissions is "prm": the opaque capability labels this link grants,
	// sorted.
	Permissions []string `json:"prm"`
	// Resources is "res": the scopes this link covers, each a sequence of
	// [kind, id] segments. Structured, never a joined string — see
	// domain.ResourceSchema.
	Resources [][][]string `json:"res"`
	// Caveats is "cav": the conditions beyond the four standard claims
	// above, sorted by kind.
	Caveats []caveat.WireCaveat `json:"cav,omitempty"`
	// Confirmation is "cnf": the key this link's children must be signed
	// by. Present on a delegation link and on no other.
	Confirmation *confirmation `json:"cnf,omitempty"`
	// ParentHash is "par_hash": the SHA-256 of the parent link's JWS
	// signing input, base64url without padding. Absent on a root link and
	// present on every other, binding each link to exactly one parent.
	ParentHash *string `json:"par_hash,omitempty"`
}

// MaxPresentationBytes bounds the whole presented chain before any parsing.
// A bearer credential is attacker-supplied; this keeps the work and memory a
// hostile presenter can demand proportional to a small, fixed input.
const MaxPresentationBytes = 64 << 10

// MaxListEntries bounds every list in a signed claim. The caveat codec
// enforces the same bound for lists inside caveat values.
const MaxListEntries = caveat.MaxListEntries

// headerOrder, claimsOrder and jwkOrder are the canonical member orders.
// The signed bytes are part of the format, so a reordered object is a
// different token and is refused rather than re-canonicalized.
var (
	headerOrder = []string{"alg", "typ"}
	claimsOrder = []string{
		"ctv", "ctt", "iss", "sub", "aud", "jti", "cid", "iat", "nbf", "exp",
		"prm", "res", "cav", "cnf", "par_hash",
	}
	jwkOrder = []string{"kty", "crv", "x"}
)

// header is a link's JOSE protected header. Two members, and nothing else
// is tolerated on the way in: no kid, jwk, jku or x5u to follow, and no
// crit, so nothing about this format depends on a library honouring one.
type header struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

// link is one decoded link of a presented chain, with the bytes it arrived
// as kept alongside, because the parent-hash linkage commits to the
// presented signing input and not to a re-encoding of it.
type link struct {
	claims  claims
	compact string
	// signing is the JWS signing input: the protected header and the
	// payload, base64url, joined by a dot. It is the parent-hash preimage.
	signing string
	// grant is the claims as the caveat layer's value.
	grant caveat.Grant
	// confirm is the decoded cnf key, nil on a terminal link.
	confirm ed25519.PublicKey
}

// signLink serializes c and signs it, returning the compact JWS.
//
// go-jose builds the protected header and the signature; this function
// controls the payload bytes, because the claim order is part of the
// format. See docs/wire-format.md, "Library choice", for why a JOSE library
// is in the trust path rather than a hand-rolled encoder.
func signLink(c claims, key crypto.Signer) (string, error) {
	if _, err := signerPublicKey(key); err != nil {
		return "", err
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("%w: claims cannot be encoded", ErrInvalidToken)
	}
	// go-jose's native Ed25519 path keeps generated tokens byte-identical to
	// the committed vectors. Any other crypto.Signer (an HSM, a KMS) goes
	// through the opaque adapter, which still asks it for an Ed25519
	// signature over the JWS signing input.
	var joseKey any = key
	if _, ok := key.(ed25519.PrivateKey); !ok {
		joseKey = cryptosigner.Opaque(key)
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(Algorithm), Key: joseKey},
		(&jose.SignerOptions{}).WithType(jose.ContentType(MediaType)),
	)
	if err != nil {
		return "", fmt.Errorf("%w: signer cannot be constructed", ErrInvalidToken)
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("%w: cannot sign", ErrInvalidToken)
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("%w: cannot serialize", ErrInvalidToken)
	}
	return compact, nil
}

// signingInput returns the compact JWS's signing input: everything before
// the final dot.
//
// It is a substring rather than a re-encoding, so the parent hash commits
// to the bytes that were actually presented and signed. Any third-party
// implementation can compute it with one lastIndexOf, which is why
// par_hash is cheap to implement correctly in another language.
func signingInput(compact string) string {
	i := strings.LastIndex(compact, ".")
	if i < 0 {
		return ""
	}
	return compact[:i]
}

// parentHash returns the base64url, unpadded SHA-256 of a signing input.
func parentHash(signing string) string {
	sum := sha256.Sum256([]byte(signing))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// present joins compact links into a presentation string.
func present(links []string) string {
	return Prefix + Separator + strings.Join(links, Separator)
}

// splitPresentation splits a presentation into its compact links, refusing
// anything that is not this format and anything longer than maxLinks.
func splitPresentation(presented string, maxLinks int) ([]string, error) {
	if len(presented) > MaxPresentationBytes {
		return nil, fmt.Errorf("%w: presentation is too large", ErrInvalidToken)
	}
	rest, ok := strings.CutPrefix(presented, Prefix+Separator)
	if !ok {
		return nil, fmt.Errorf("%w: not a captoken presentation", ErrInvalidToken)
	}
	parts := strings.Split(rest, Separator)
	if len(parts) == 0 || len(parts) > maxLinks {
		return nil, fmt.Errorf("%w: chain length out of range", ErrInvalidToken)
	}
	for _, p := range parts {
		// Exactly three segments: a compact JWS with one signature. A JSON
		// serialization, a detached payload or an unprotected header are
		// all refused rather than interpreted.
		if strings.Count(p, ".") != 2 || p == "" {
			return nil, fmt.Errorf("%w: link is not a compact JWS", ErrInvalidToken)
		}
	}
	return parts, nil
}

// parseHeader decodes and validates a link's protected header. The header
// must consist of exactly alg and typ, with exactly the pinned values.
func parseHeader(compact string) error {
	segment, _, ok := strings.Cut(compact, ".")
	if !ok {
		return fmt.Errorf("%w: link is not a compact JWS", ErrInvalidToken)
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(segment)
	if err != nil {
		return fmt.Errorf("%w: header is not base64url", ErrInvalidToken)
	}
	if err := requireMemberOrder(raw, headerOrder); err != nil {
		return err
	}
	if err := rejectDuplicateKeys(raw); err != nil {
		return err
	}
	var h header
	if err := strictUnmarshal(raw, &h); err != nil {
		return err
	}
	if err := requireCanonicalJSON(raw, h); err != nil {
		return err
	}
	// Compared for equality against a constant, never used to select a key
	// or a verification routine. That is the discipline that closes the
	// algorithm-confusion family, and it is why there is no table here.
	if h.Algorithm != Algorithm {
		return fmt.Errorf("%w: unsupported algorithm", ErrInvalidToken)
	}
	if h.Type != MediaType {
		return fmt.Errorf("%w: unsupported media type", ErrInvalidToken)
	}
	return nil
}

// parseClaims decodes a link's payload without checking its signature.
//
// Nothing outside this package can reach it, which is deliberate: cas's
// equivalent split (Parse, then Verify) made it possible to inspect a
// token's contents before authorizing it, and the Biscuit spike recorded
// the same hazard in biscuit-go, whose Unmarshal does no signature
// checking at all. An API that lets a caller read an unverified token's
// claims is a bypass waiting to be written, so there isn't one.
func parseClaims(compact string) (claims, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return claims{}, fmt.Errorf("%w: link is not a compact JWS", ErrInvalidToken)
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil {
		return claims{}, fmt.Errorf("%w: payload is not base64url", ErrInvalidToken)
	}
	if err := requireMemberOrder(raw, claimsOrder); err != nil {
		return claims{}, err
	}
	if err := rejectDuplicateKeys(raw); err != nil {
		return claims{}, err
	}
	var c claims
	if err := strictUnmarshal(raw, &c); err != nil {
		return claims{}, err
	}
	if err := requireCanonicalJSON(raw, c); err != nil {
		return claims{}, err
	}
	return c, nil
}

// verifySignature checks a link's signature under pub, with the algorithm
// pinned by the allowlist go-jose is given.
func verifySignature(compact string, pub ed25519.PublicKey) error {
	if err := validatePublicKey(pub); err != nil {
		return err
	}
	parsed, err := jose.ParseSigned(compact, []jose.SignatureAlgorithm{jose.SignatureAlgorithm(Algorithm)})
	if err != nil {
		return fmt.Errorf("%w: link does not parse", ErrInvalidToken)
	}
	if len(parsed.Signatures) != 1 {
		return fmt.Errorf("%w: link does not carry exactly one signature", ErrInvalidToken)
	}
	if _, err := parsed.Verify(pub); err != nil {
		return fmt.Errorf("%w: signature does not verify", ErrInvalidToken)
	}
	return nil
}

// decodeLink parses, validates and structurally checks one link, without
// checking its signature — the caller does that, because which key to use
// depends on the link before it.
func decodeLink(compact string, schema domain.ResourceSchema, checkVersion bool) (link, error) {
	if err := parseHeader(compact); err != nil {
		return link{}, err
	}
	c, err := parseClaims(compact)
	if err != nil {
		return link{}, err
	}
	if checkVersion && c.Version != FormatVersion {
		return link{}, fmt.Errorf("%w: unsupported format version", ErrInvalidToken)
	}
	if !TokenType(c.Type).valid() {
		return link{}, fmt.Errorf("%w: unknown token type", ErrInvalidToken)
	}
	grant, err := grantFrom(c, schema)
	if err != nil {
		return link{}, err
	}

	l := link{claims: c, compact: compact, signing: signingInput(compact), grant: grant}

	switch {
	case TokenType(c.Type) == TypeDelegation:
		if c.Confirmation == nil {
			// A delegation token with no bound key authorises derivation
			// by nobody, which is not a narrower delegation token — it is
			// a malformed one, and tolerating it would make the chain's
			// key linkage optional.
			return link{}, fmt.Errorf("%w: delegation link binds no key", ErrInvalidToken)
		}
		pub, kerr := decodeJWK(c.Confirmation.JWK)
		if kerr != nil {
			return link{}, kerr
		}
		l.confirm = pub
	default:
		if c.Confirmation != nil {
			// A terminal token that bound a key would be derivable, which
			// is exactly what its type says it is not.
			return link{}, fmt.Errorf("%w: terminal link binds a key", ErrInvalidToken)
		}
		if len(c.Audience) == 0 {
			return link{}, fmt.Errorf("%w: terminal link names no audience", ErrInvalidToken)
		}
	}
	return l, nil
}

// grantFrom builds the caveat layer's view of a link's claims.
func grantFrom(c claims, schema domain.ResourceSchema) (caveat.Grant, error) {
	if _, err := domain.ParseID("issuer", c.Issuer); err != nil {
		return caveat.Grant{}, fmt.Errorf("%w: malformed issuer", ErrInvalidToken)
	}
	if _, err := domain.ParseID("subject", c.Subject); err != nil {
		return caveat.Grant{}, fmt.Errorf("%w: malformed subject", ErrInvalidToken)
	}
	if _, err := domain.ParseID("token id", c.TokenID); err != nil {
		return caveat.Grant{}, fmt.Errorf("%w: malformed token id", ErrInvalidToken)
	}
	if _, err := domain.ParseID("chain id", c.ChainID); err != nil {
		return caveat.Grant{}, fmt.Errorf("%w: malformed chain id", ErrInvalidToken)
	}
	for _, aud := range c.Audience {
		if _, err := domain.ParseID("audience", aud); err != nil {
			return caveat.Grant{}, fmt.Errorf("%w: malformed audience", ErrInvalidToken)
		}
	}
	if len(c.Audience) > MaxListEntries {
		return caveat.Grant{}, fmt.Errorf("%w: too many audiences", ErrInvalidToken)
	}
	if !slices.IsSorted(c.Audience) || len(slices.Compact(slices.Clone(c.Audience))) != len(c.Audience) {
		return caveat.Grant{}, fmt.Errorf("%w: audience is not canonical", ErrInvalidToken)
	}
	const maxNumericDate = 1 << 40 // about 34,000 years
	if c.IssuedAt <= 0 || c.IssuedAt > maxNumericDate {
		return caveat.Grant{}, fmt.Errorf("%w: issue time is out of range", ErrInvalidToken)
	}
	if c.ExpiresAt <= 0 || c.ExpiresAt > maxNumericDate {
		return caveat.Grant{}, fmt.Errorf("%w: expiry is out of range", ErrInvalidToken)
	}
	if c.NotBefore != nil && (*c.NotBefore < 0 || *c.NotBefore > maxNumericDate) {
		return caveat.Grant{}, fmt.Errorf("%w: not-before is out of range", ErrInvalidToken)
	}
	if len(c.Permissions) == 0 {
		return caveat.Grant{}, fmt.Errorf("%w: grants no permission", ErrInvalidToken)
	}
	if len(c.Permissions) > MaxListEntries {
		return caveat.Grant{}, fmt.Errorf("%w: too many permissions", ErrInvalidToken)
	}
	if !slices.IsSorted(c.Permissions) || len(slices.Compact(slices.Clone(c.Permissions))) != len(c.Permissions) {
		return caveat.Grant{}, fmt.Errorf("%w: permissions are not canonical", ErrInvalidToken)
	}

	perms := make([]domain.Permission, len(c.Permissions))
	for i, p := range c.Permissions {
		parsed, err := domain.ParsePermission(p)
		if err != nil {
			return caveat.Grant{}, fmt.Errorf("%w: malformed permission", ErrInvalidToken)
		}
		perms[i] = parsed
	}
	resources, err := caveat.DecodePaths(c.Resources, schema)
	if err != nil {
		return caveat.Grant{}, fmt.Errorf("%w: malformed resource scope", ErrInvalidToken)
	}
	caveats, err := caveat.DecodeAll(c.Caveats, schema)
	if err != nil {
		return caveat.Grant{}, fmt.Errorf("%w: malformed caveat", ErrInvalidToken)
	}
	for _, cav := range caveats {
		if caveat.HasStandardClaim(cav.Kind()) {
			// docs/wire-format.md: the four kinds with a standard-claim
			// counterpart are carried ONLY as exp, nbf, prm and res, and a
			// verifier MUST refuse one that appears in cav. A token saying
			// expires_at in both places says one thing to a reader of the
			// claims and another to a reader of the caveat array, and
			// nothing requires the two to agree — so a verifier that took
			// the lenient reading would disagree with a conforming one
			// about what the token permits.
			return caveat.Grant{}, fmt.Errorf("%w: a standard claim appears as a caveat entry", ErrInvalidToken)
		}
	}

	g := caveat.Grant{
		Subject:     domain.Subject(c.Subject),
		Permissions: domain.NewPermissionSet(perms...),
		Resources:   resources,
		ExpiresAt:   time.Unix(c.ExpiresAt, 0).UTC(),
		Caveats:     caveats,
	}
	if c.NotBefore != nil {
		g.NotBefore = time.Unix(*c.NotBefore, 0).UTC()
	}
	return g, nil
}

// requireCanonicalJSON re-encodes a decoded value and requires the exact
// bytes to match. It rejects whitespace, redundant escapes and any other
// spelling that a conforming encoder would not produce: the signed bytes are
// the format, and two spellings of one claim set would be two credentials.
func requireCanonicalJSON(raw []byte, value any) error {
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, raw) {
		return fmt.Errorf("%w: JSON is not canonical", ErrInvalidToken)
	}
	return nil
}

// requireMemberOrder refuses a JSON object whose members are not a
// subsequence of canonical, in canonical order. Optional members may be
// absent, but a present member may not move.
func requireMemberOrder(raw []byte, canonical []string) error {
	rank := make(map[string]int, len(canonical))
	for i, name := range canonical {
		rank[name] = i
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("%w: malformed JSON object", ErrInvalidToken)
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return fmt.Errorf("%w: expected a JSON object", ErrInvalidToken)
	}
	last := -1
	for dec.More() {
		tok, err = dec.Token()
		if err != nil {
			return fmt.Errorf("%w: malformed JSON object", ErrInvalidToken)
		}
		name, ok := tok.(string)
		if !ok {
			return fmt.Errorf("%w: malformed member name", ErrInvalidToken)
		}
		index, ok := rank[name]
		if !ok || index <= last {
			return fmt.Errorf("%w: members are not in canonical order", ErrInvalidToken)
		}
		last = index
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return fmt.Errorf("%w: malformed member value", ErrInvalidToken)
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("%w: member %q is null", ErrInvalidToken, name)
		}
	}
	if _, err := dec.Token(); err != nil {
		return fmt.Errorf("%w: malformed JSON object", ErrInvalidToken)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing content", ErrInvalidToken)
	}
	return nil
}

// strictUnmarshal decodes JSON into dst, refusing an unknown member and
// refusing trailing content.
//
// Refusing unknown members is the fail-closed reading of a format that has
// a version claim: a build that meets a member it does not know is a build
// that does not implement the token's format, and the honest answer is to
// refuse rather than to evaluate the part it recognized. A consumer with
// its own claims to carry puts them in its own token, not in this one.
func strictUnmarshal(raw []byte, dst any) error {
	if !utf8.Valid(raw) {
		return fmt.Errorf("%w: claims are not valid UTF-8", ErrInvalidToken)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("%w: malformed claims", ErrInvalidToken)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing content", ErrInvalidToken)
	}
	return nil
}

// rejectDuplicateKeys refuses a JSON object that names the same member
// twice, at any depth.
//
// encoding/json accepts duplicates and keeps the last, and other
// implementations keep the first. A token whose meaning depends on which
// library reads it is not a token: {"ctt":"execution","ctt":"delegation"}
// must be refused by everyone rather than meaning two things. RFC 8725
// says the same and no mainstream library enforces it, so this module does.
func rejectDuplicateKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()

	// One frame per container currently open. Tracking whether the
	// innermost container is an object is what distinguishes a member name
	// from a string VALUE — without it, a string inside an array nested in
	// an object reads as a member name and the check is nonsense.
	type frame struct {
		isObject bool
		seen     map[string]struct{}
	}
	var stack []frame
	expectKey := false

	inObject := func() bool { return len(stack) > 0 && stack[len(stack)-1].isObject }

	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%w: malformed claims", ErrInvalidToken)
		}

		if delim, ok := tok.(json.Delim); ok {
			switch delim {
			case '{':
				stack = append(stack, frame{isObject: true, seen: map[string]struct{}{}})
				expectKey = true
			case '[':
				stack = append(stack, frame{})
				expectKey = false
			case '}', ']':
				if len(stack) == 0 {
					return fmt.Errorf("%w: malformed claims", ErrInvalidToken)
				}
				stack = stack[:len(stack)-1]
				expectKey = inObject()
			}
			continue
		}

		if name, ok := tok.(string); ok && expectKey && inObject() {
			seen := stack[len(stack)-1].seen
			if _, dup := seen[name]; dup {
				return fmt.Errorf("%w: duplicate member", ErrInvalidToken)
			}
			seen[name] = struct{}{}
			expectKey = false
			continue
		}
		expectKey = inObject()
	}
}
